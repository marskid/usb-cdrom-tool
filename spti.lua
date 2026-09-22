-- spti.lua
-- LuaJIT Windows SCSI Pass-Through Direct (SPTI) 脚本
-- 列出 CD-ROM 设备并通过 SCSI 直通写入数据
-- https://github.com/marskid/usb-cdrom-tool

-- Copyright (C) 2026  marskid

-- This file is part of spti.lua.

-- spti.lua is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.

-- spti.lua is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.

-- You should have received a copy of the GNU General Public License
-- along with spti.lua.  If not, see <https://www.gnu.org/licenses/>.

local ffi = require("ffi")
local bit = require("bit")

-- ============================================================================
-- Windows API 定义
-- ============================================================================

ffi.cdef[[
    typedef unsigned char       UCHAR;
    typedef unsigned short      USHORT;
    typedef unsigned long       ULONG;
    typedef unsigned int        UINT;
    typedef unsigned long long  ULONG_PTR;
    typedef int                 BOOL;
    typedef unsigned long       DWORD;
    typedef void*               HANDLE;
    typedef void*               LPVOID;
    typedef const char*         LPCSTR;
    typedef char*               LPSTR;
    typedef size_t              SIZE_T;

    typedef struct _SECURITY_ATTRIBUTES {
        DWORD  nLength;
        LPVOID lpSecurityDescriptor;
        BOOL   bInheritHandle;
    } SECURITY_ATTRIBUTES;

    typedef struct _OVERLAPPED {
        ULONG_PTR Internal;
        ULONG_PTR InternalHigh;
        union {
            struct {
                DWORD Offset;
                DWORD OffsetHigh;
            };
            LPVOID Pointer;
        };
        HANDLE hEvent;
    } OVERLAPPED;

    typedef struct _SCSI_PASS_THROUGH_DIRECT {
        USHORT Length;
        UCHAR  ScsiStatus;
        UCHAR  PathId;
        UCHAR  TargetId;
        UCHAR  Lun;
        UCHAR  CdbLength;
        UCHAR  SenseInfoLength;
        UCHAR  DataIn;
        ULONG  DataTransferLength;
        ULONG  TimeOutValue;
        LPVOID DataBuffer;
        ULONG  SenseInfoOffset;
        UCHAR  Cdb[16];
    } SCSI_PASS_THROUGH_DIRECT, *PSCSI_PASS_THROUGH_DIRECT;

    typedef struct _SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER {
        SCSI_PASS_THROUGH_DIRECT sptd;
        ULONG Filler;
        UCHAR SenseBuffer[32];
    } SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER, *PSCSI_PASS_THROUGH_DIRECT_WITH_BUFFER;

    HANDLE CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess,
                       DWORD dwShareMode, SECURITY_ATTRIBUTES* lpSecurityAttributes,
                       DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes,
                       HANDLE hTemplateFile);
    BOOL CloseHandle(HANDLE hObject);
    BOOL DeviceIoControl(HANDLE hDevice, DWORD dwIoControlCode,
                         LPVOID lpInBuffer, DWORD nInBufferSize,
                         LPVOID lpOutBuffer, DWORD nOutBufferSize,
                         DWORD* lpBytesReturned, OVERLAPPED* lpOverlapped);
    DWORD GetLastError(void);

    UINT GetDriveTypeA(LPCSTR lpRootPathName);
    DWORD GetLogicalDriveStringsA(DWORD nBufferLength, LPSTR lpBuffer);
    BOOL GetVolumeInformationA(LPCSTR lpRootPathName,
                                LPSTR lpVolumeNameBuffer, DWORD nVolumeNameSize,
                                DWORD* lpVolumeSerialNumber,
                                DWORD* lpMaximumComponentLength,
                                DWORD* lpFileSystemFlags,
                                LPSTR lpFileSystemNameBuffer,
                                DWORD nFileSystemNameSize);
    DWORD QueryDosDeviceA(LPCSTR lpDeviceName, LPSTR lpTargetPath, DWORD ucchMax);

    BOOL QueryPerformanceCounter(ULONG_PTR* lpPerformanceCount);
    BOOL QueryPerformanceFrequency(ULONG_PTR* lpFrequency);
]]

-- ============================================================================
-- 常量定义
-- ============================================================================

local DEF_CHUNK_BLOCKS    = 32                          -- 默认 32 块 = 64KB
local PROBE_CANDIDATES    = {256, 128, 64, 32, 16, 8, 4} -- 从大到小试
local PROBED_CHUNK        = {}                          -- device_path -> 块数 缓存

local IOCTL_SCSI_PASS_THROUGH_DIRECT = 0x4D014

local SCSI_IOCTL_DATA_OUT         = 0
local SCSI_IOCTL_DATA_IN          = 1
local SCSI_IOCTL_DATA_UNSPECIFIED = 2

local SCSI_OP_INQUIRY             = 0x12
local SCSI_OP_READ_CAPACITY       = 0x25
local SCSI_OP_READ_10             = 0x28
local SCSI_OP_WRITE_10            = 0x2A
local SCSI_OP_WRITE_12            = 0xAA
local SCSI_OP_MODE_SENSE_10       = 0x5A
local SCSI_OP_SYNCHRONIZE_CACHE   = 0x35
local SCSI_OP_PREVENT_ALLOW       = 0x1E

local GENERIC_READ          = 0x80000000
local GENERIC_WRITE         = 0x40000000
local FILE_SHARE_READ       = 0x00000001
local FILE_SHARE_WRITE      = 0x00000002
local OPEN_EXISTING         = 3
local FILE_ATTRIBUTE_NORMAL = 0x00000080

-- 64 位安全的 INVALID_HANDLE_VALUE (0xFFFFFFFFFFFFFFFF)
-- 原 ffi.cast("HANDLE", -1) 在 64 位上会丢精度
local INVALID_HANDLE_VALUE = ffi.cast("HANDLE", 0xFFFFFFFFFFFFFFFFULL)

-- ============================================================================
-- 辅助函数
-- ============================================================================

local function last_err()
    local err = ffi.C.GetLastError()
    return string.format("Windows Error 0x%X (%d)", err, err)
end

local function hex_dump(buf, len, offset)
    offset = offset or 0
    local lines = {}
    for i = 0, len - 1, 16 do
        local hex_parts, ascii_parts = {}, {}
        for j = 0, 15 do
            if i + j < len then
                local byte = buf[offset + i + j]
                hex_parts[#hex_parts + 1] = string.format("%02X", byte)
                ascii_parts[#ascii_parts + 1] =
                    (byte >= 32 and byte < 127) and string.char(byte) or "."
            else
                hex_parts[#hex_parts + 1] = "  "
                ascii_parts[#ascii_parts + 1] = " "
            end
        end
        lines[#lines + 1] = string.format("%08X  %s  %s",
            i, table.concat(hex_parts, " "), table.concat(ascii_parts))
    end
    return table.concat(lines, "\n")
end

-- 高精度墙上时钟（秒），用 QPC 实现；失败回退 os.time()
-- 注意：Windows 上 os.clock() 返回的是 CPU 时间，IO 密集场景会大幅低估，不能用于 IO 计时
local QPC_FREQ  -- nil = 未初始化, false = 不可用, number = 频率

local function wall_clock()
    if QPC_FREQ == nil then
        local freq = ffi.new("ULONG_PTR[1]")
        if ffi.C.QueryPerformanceFrequency(freq) ~= 0 and freq[0] ~= 0 then
            QPC_FREQ = tonumber(freq[0])
        else
            QPC_FREQ = false
        end
    end
    if QPC_FREQ then
        local counter = ffi.new("ULONG_PTR[1]")
        if ffi.C.QueryPerformanceCounter(counter) ~= 0 then
            return tonumber(counter[0]) / QPC_FREQ
        end
    end
    return os.time()
end

-- 大端编码助手（push 风格：向表尾追加）
-- 避免 Lua 多返回值在表构造里被截断的陷阱
-- （函数调用如果不是表构造的最后一个表达式，只取第一个返回值）
local function push_be32(t, value)
    t[#t + 1] = bit.band(bit.rshift(value, 24), 0xFF)
    t[#t + 1] = bit.band(bit.rshift(value, 16), 0xFF)
    t[#t + 1] = bit.band(bit.rshift(value, 8), 0xFF)
    t[#t + 1] = bit.band(value, 0xFF)
end

local function push_be16(t, value)
    t[#t + 1] = bit.band(bit.rshift(value, 8), 0xFF)
    t[#t + 1] = bit.band(value, 0xFF)
end

-- 统一解析 --verify / --write12 / --chunk=N 选项
local function parse_options(args, start_idx)
    local opt = { verify = false, use_write12 = false, chunk = nil }
    for i = start_idx, #args do
        local a = args[i]
        if a == "--verify" then
            opt.verify = true
        elseif a == "--write12" then
            opt.use_write12 = true
        elseif a:match("^%-%-chunk=") then
            opt.chunk = tonumber(a:match("=(%d+)"))
        end
    end
    return opt
end

-- ============================================================================
-- SCSI sense data 解析
-- ============================================================================

local SENSE_KEY_NAMES = {
    [0x00] = "NO_SENSE",
    [0x01] = "RECOVERED_ERROR",
    [0x02] = "NOT_READY",
    [0x03] = "MEDIUM_ERROR",
    [0x04] = "HARDWARE_ERROR",
    [0x05] = "ILLEGAL_REQUEST",
    [0x06] = "UNIT_ATTENTION",
    [0x07] = "DATA_PROTECT",
    [0x08] = "BLANK_CHECK",
    [0x09] = "VENDOR_SPECIFIC",
    [0x0A] = "COPY_ABORTED",
    [0x0B] = "ABORTED_COMMAND",
    [0x0C] = "VOLUME_OVERFLOW",
    [0x0D] = "MISCOMPARE",
    [0x0E] = "COMPLETED",
}

local ASC_DESC = {
    [0x0000] = "no additional sense information",
    [0x0400] = "logical unit not ready, cause not reportable",
    [0x0401] = "logical unit is in process of becoming ready",
    [0x0402] = "logical unit not ready, initializing command required",
    [0x0403] = "logical unit not ready, manual intervention required",
    [0x0404] = "logical unit not ready, formatting in progress",
    [0x3A00] = "Medium not present (no disc/tape loaded)",
    [0x3A01] = "medium not present - tray closed",
    [0x3A02] = "medium not present - tray open",
    [0x5300] = "medium load or eject failed",
    [0x5700] = "unable to recover table-of-contents",
    [0x6F00] = "copying error",
    [0x2700] = "write protected",
    [0x2707] = "write protect - resetting to write-protect",
    [0x2800] = "not ready to ready change, medium may have changed",
    [0x2900] = "power on, reset, or bus device reset occurred",
    [0x2E00] = "insufficient time for recovery",
    [0x3000] = "incompatible medium installed",
    [0x3001] = "cannot read medium - unknown format",
    [0x3002] = "cannot read medium - incompatible format",
    [0x3700] = "rounded parameter",
    [0x3D00] = "invalid bits in identify message",
    [0x2000] = "invalid command operation code",
    [0x2100] = "logical block address out of range",
    [0x2500] = "logical unit not supported",
    [0x1C00] = "data protect",
    [0x4400] = "internal target failure",
    [0x5302] = "medium removal prevented",
    [0x8202] = "medium may have changed",
}

-- 解析固定格式 SCSI sense data，返回可读字符串
local function parse_sense(sense_buf, sense_len)
    if not sense_buf or sense_len < 14 then
        return "(no sense data)"
    end
    local response_code = bit.band(sense_buf[0], 0x7F)
    if response_code ~= 0x70 and response_code ~= 0x71 then
        return string.format("(unknown sense response code 0x%02X)", response_code)
    end

    local sense_key = bit.band(sense_buf[2], 0x0F)
    local asc       = sense_buf[12]
    local ascq      = sense_buf[13]

    local key_name  = SENSE_KEY_NAMES[sense_key] or
        string.format("UNKNOWN(0x%02X)", sense_key)
    local asc_key   = asc * 256 + ascq
    local asc_desc  = ASC_DESC[asc_key] or
        string.format("ASC=0x%02X ASCQ=0x%02X", asc, ascq)

    return string.format("%s (key=0x%02X, %s)", key_name, sense_key, asc_desc)
end

-- ============================================================================
-- SCSI 直通类
-- ============================================================================

local ScsiPT = {}
ScsiPT.__index = ScsiPT

function ScsiPT.new(device_path)
    local self = setmetatable({}, ScsiPT)
    self.device_path     = device_path
    -- 可复用的传输结构（单实例，不再每次新建）
    self.sptd            = ffi.new("SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER")
    -- 可复用的 bytes_returned，不再每次 ffi.new("DWORD[1]")
    self.bytes_returned  = ffi.new("DWORD[1]")
    -- 可按需增长的数据缓冲区，read10/write10/write12/inquiry/mode_sense10 共用
    self.data_buf        = nil
    self.data_buf_size   = 0
    -- 探测失败时记录最后一次错误，供 resolve_chunk 打印首行
    self.probe_last_err  = nil

    local access = bit.bor(GENERIC_READ, GENERIC_WRITE)

    local handle = ffi.C.CreateFileA(
        device_path,
        access,
        bit.bor(FILE_SHARE_READ, FILE_SHARE_WRITE),
        nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nil
    )

    if handle == INVALID_HANDLE_VALUE then
        return nil, "无法打开设备 " .. device_path .. ": " .. last_err()
    end
    -- GC 兜底：忘记 close 时也保证句柄被释放
    self.handle = ffi.gc(handle, function(h)
        if h ~= nil and h ~= INVALID_HANDLE_VALUE then
            ffi.C.CloseHandle(h)
        end
    end)
    return self
end

function ScsiPT:close()
    if self.handle and self.handle ~= INVALID_HANDLE_VALUE then
        ffi.gc(self.handle, nil)        -- 取消 finalizer，避免重复关闭
        ffi.C.CloseHandle(self.handle)
    end
    self.handle         = nil
    self.sptd           = nil
    self.bytes_returned = nil
    self.data_buf       = nil
    self.data_buf_size  = 0
end

-- 保证 self.data_buf 至少 size 字节；不够就重新分配
function ScsiPT:ensure_buf(size)
    if not self.data_buf or self.data_buf_size < size then
        self.data_buf      = ffi.new("UCHAR[?]", size)
        self.data_buf_size = size
    end
    return self.data_buf
end

function ScsiPT:execute(cdb, data_buf, data_len, data_direction, timeout)
    timeout        = timeout or 60
    data_len       = data_len or 0
    data_direction = data_direction or SCSI_IOCTL_DATA_UNSPECIFIED

    local sptd      = self.sptd
    local sptd_size = ffi.sizeof("SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER")
    ffi.fill(sptd, sptd_size, 0)

    sptd.sptd.Length              = ffi.sizeof("SCSI_PASS_THROUGH_DIRECT")
    sptd.sptd.CdbLength          = #cdb
    sptd.sptd.SenseInfoLength    = 32
    sptd.sptd.DataIn             = data_direction
    sptd.sptd.DataTransferLength = data_len
    sptd.sptd.TimeOutValue       = timeout
    sptd.sptd.DataBuffer         = data_buf or nil
    sptd.sptd.SenseInfoOffset    =
        ffi.offsetof("SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER", "SenseBuffer")

    for i = 1, #cdb do
        sptd.sptd.Cdb[i - 1] = cdb[i]
    end

    local result = ffi.C.DeviceIoControl(
        self.handle,
        IOCTL_SCSI_PASS_THROUGH_DIRECT,
        sptd, sptd_size,
        sptd, sptd_size,
        self.bytes_returned, nil
    )

    if result == 0 then
        local err        = last_err()
        local sense_str  = parse_sense(sptd.SenseBuffer, 32)
        local raw_sense  = hex_dump(sptd.SenseBuffer, 32)
        return nil, string.format(
            "DeviceIoControl 失败: %s\n  CdbLength=%d DataIn=%d DataTransferLength=%d\n  Sense: %s\n  Raw sense:\n%s",
            err,
            sptd.sptd.CdbLength,
            sptd.sptd.DataIn,
            sptd.sptd.DataTransferLength,
            sense_str, raw_sense)
    end

    if sptd.sptd.ScsiStatus ~= 0 then
        local sense_str = parse_sense(sptd.SenseBuffer, 32)
        local raw_sense = hex_dump(sptd.SenseBuffer, 32)
        return nil, string.format("SCSI 状态: 0x%02X\n  Sense: %s\n  Raw sense:\n%s",
            sptd.sptd.ScsiStatus, sense_str, raw_sense)
    end

    return true
end

function ScsiPT:inquiry(evpd, page_code, alloc_len)
    alloc_len = alloc_len or 36
    evpd      = evpd and 1 or 0
    page_code = page_code or 0

    local data_buf = self:ensure_buf(alloc_len)
    -- INQUIRY CDB (6 字节): opcode, EVPD/page, page_code, reserved, alloc_len(1 字节), control
    -- 注意：INQUIRY 是 6 字节短 CDB，分配长度只有 8 位，不能用 push_be16
    -- （push_be16 会编成 7 字节，设备读到的分配长度变成 0，导致超时 60 秒）
    local cdb = {SCSI_OP_INQUIRY, evpd, page_code, 0,
                 bit.band(alloc_len, 0xFF), 0}

    local ok, err = self:execute(cdb, data_buf, alloc_len, SCSI_IOCTL_DATA_IN)
    if not ok then return nil, err end

    -- 返回 Lua 字符串（用 ffi.string，不再逐字节构造 Lua 表）
    return ffi.string(data_buf, alloc_len)
end

function ScsiPT:read_capacity_10()
    local alloc_len = 8
    local data_buf = self:ensure_buf(alloc_len)
    local cdb = {SCSI_OP_READ_CAPACITY, 0, 0, 0, 0, 0, 0, 0, 0, 0}

    local ok, err = self:execute(cdb, data_buf, alloc_len, SCSI_IOCTL_DATA_IN)
    if not ok then return nil, err end

    local last_lba = bit.bor(
        bit.lshift(data_buf[0], 24), bit.lshift(data_buf[1], 16),
        bit.lshift(data_buf[2], 8),  data_buf[3])
    local block_size = bit.bor(
        bit.lshift(data_buf[4], 24), bit.lshift(data_buf[5], 16),
        bit.lshift(data_buf[6], 8),  data_buf[7])

    return {
        last_lba   = last_lba,
        block_size = block_size,
        num_blocks = last_lba + 1,
    }
end

function ScsiPT:read10(lba, num_blocks, block_size)
    local data_len = num_blocks * block_size
    local data_buf = self:ensure_buf(data_len)

    -- READ(10) CDB (10 字节): opcode, flags, LBA(4 BE), reserved, count(2 BE), control
    local cdb = {SCSI_OP_READ_10, 0}
    push_be32(cdb, lba)
    cdb[#cdb + 1] = 0
    push_be16(cdb, num_blocks)
    cdb[#cdb + 1] = 0

    local ok, err = self:execute(cdb, data_buf, data_len, SCSI_IOCTL_DATA_IN)
    if not ok then return nil, err end
    return ffi.string(data_buf, data_len)
end

function ScsiPT:write10(lba, data, block_size)
    local num_blocks = math.floor(#data / block_size)
    if num_blocks == 0 then return nil, "数据太小，必须至少一个块大小" end

    local data_len = num_blocks * block_size
    local data_buf = self:ensure_buf(data_len)
    ffi.copy(data_buf, data, data_len)

    -- WRITE(10) CDB (10 字节): opcode, flags, LBA(4 BE), reserved, count(2 BE), control
    local cdb = {SCSI_OP_WRITE_10, 0}
    push_be32(cdb, lba)
    cdb[#cdb + 1] = 0
    push_be16(cdb, num_blocks)
    cdb[#cdb + 1] = 0

    local ok, err = self:execute(cdb, data_buf, data_len, SCSI_IOCTL_DATA_OUT)
    if not ok then return nil, err end
    return num_blocks
end

function ScsiPT:write12(lba, data, block_size)
    local num_blocks = math.floor(#data / block_size)
    if num_blocks == 0 then return nil, "数据太小" end

    local data_len = num_blocks * block_size
    local data_buf = self:ensure_buf(data_len)
    ffi.copy(data_buf, data, data_len)

    -- WRITE(12) CDB (12 字节):
    --   0:    opcode (0xAA)
    --   1:    flags
    --   2-5:  LBA (4 字节大端)  ← 注意只有 4 字节，不是 5 字节
    --   6:    reserved
    --   7-10: transfer length (4 字节大端)
    --   11:   control
    local cdb = {SCSI_OP_WRITE_12, 0}
    push_be32(cdb, lba)
    cdb[#cdb + 1] = 0                       -- reserved
    push_be32(cdb, num_blocks)
    cdb[#cdb + 1] = 0                       -- control

    local ok, err = self:execute(cdb, data_buf, data_len, SCSI_IOCTL_DATA_OUT)
    if not ok then return nil, err end
    return num_blocks
end

function ScsiPT:mode_sense10(page_code)
    page_code = page_code or 0x3F
    local alloc_len = 256
    local data_buf = self:ensure_buf(alloc_len)

    -- MODE SENSE(10) CDB (10 字节): opcode, flags, page_code, reserved(4), alloc_len(2 BE), control
    local cdb = {SCSI_OP_MODE_SENSE_10, 0, page_code, 0, 0, 0, 0}
    push_be16(cdb, alloc_len)
    cdb[#cdb + 1] = 0

    local ok, err = self:execute(cdb, data_buf, alloc_len, SCSI_IOCTL_DATA_IN)
    if not ok then return nil, err end

    return ffi.string(data_buf, alloc_len)
end

function ScsiPT:sync_cache()
    local cdb = {SCSI_OP_SYNCHRONIZE_CACHE, 0, 0, 0, 0, 0, 0, 0, 0, 0}
    return self:execute(cdb, nil, 0, SCSI_IOCTL_DATA_UNSPECIFIED)
end

function ScsiPT:prevent_allow(prevent)
    local cdb = {SCSI_OP_PREVENT_ALLOW, 0, 0, 0, prevent and 1 or 0, 0}
    return self:execute(cdb, nil, 0, SCSI_IOCTL_DATA_UNSPECIFIED)
end

function ScsiPT:probe_max_chunk(block_size, lba)
    local key = self.device_path
    if PROBED_CHUNK[key] then return PROBED_CHUNK[key] end

    local cap = self:read_capacity_10()
    if not cap then return nil end
    local total = cap.num_blocks

    for _, n in ipairs(PROBE_CANDIDATES) do
        if n <= total then
            local data, err = self:read10(lba or 0, n, block_size)
            if data then
                PROBED_CHUNK[key] = n
                return n
            else
                self.probe_last_err = err
            end
        end
    end
    return nil
end

-- ============================================================================
-- chunk 探测（writeiso / writezero 共用）
-- ============================================================================

-- 统一解析本次操作使用的 chunk_blocks
-- 若用户指定 --chunk=N 则直接用；否则探测（带缓存），探测失败回退 DEF_CHUNK_BLOCKS
-- pt 非空时复用该 pt 做探测；为空则临时开一个
-- 返回 chunk_blocks（数字）
local function resolve_chunk(device_path, block_size, user_chunk, pt)
    if user_chunk then
        print(string.format("  手动指定 chunk: %d 块 (%d KB)",
            user_chunk, user_chunk * block_size / 1024))
        return user_chunk
    end

    local cached = PROBED_CHUNK[device_path]
    if cached then
        print(string.format("  使用探测缓存: %d 块 (%d KB)",
            cached, cached * block_size / 1024))
        return cached
    end

    local owns_pt = false
    if not pt then
        pt = ScsiPT.new(device_path)
        if not pt then
            print(string.format("  [警告] 探测打开设备失败，使用默认 %d 块", DEF_CHUNK_BLOCKS))
            return DEF_CHUNK_BLOCKS
        end
        owns_pt = true
    end

    local n = pt:probe_max_chunk(block_size, 0)
    local last_err = pt.probe_last_err
    if owns_pt then pt:close() end

    if n then
        print(string.format("  探测到最大传输: %d 块 (%d KB)",
            n, n * block_size / 1024))
        return n
    end

    -- 探测失败时，把首行错误带出来打印
    local first_line = ""
    if last_err then
        first_line = last_err:match("^([^\n]+)") or ""
    end
    if first_line ~= "" then
        first_line = " (" .. first_line .. ")"
    end
    print(string.format("  [警告] 探测失败%s，使用默认 %d 块 (%d KB)",
        first_line, DEF_CHUNK_BLOCKS, DEF_CHUNK_BLOCKS * block_size / 1024))
    return DEF_CHUNK_BLOCKS
end

-- ============================================================================
-- 通用写入 / 验证循环
-- ============================================================================

-- 通用写入循环
--   get_chunk: function(offset_bytes, this_bytes) -> data_string（长度可小于 this_bytes，会自动补零）
--   label:     错误消息前缀（可空字符串）
-- 返回: ok, err, total_written, start_time
local function write_chunks(pt, start_lba, total_blocks, block_size,
                            chunk_blocks, use_write12, get_chunk, label)
    local start_time    = wall_clock()
    local total_written = 0
    local cur_lba       = start_lba
    local end_lba       = start_lba + total_blocks

    while cur_lba < end_lba do
        local remaining   = end_lba - cur_lba
        local this_blocks  = math.min(chunk_blocks, remaining)
        local this_bytes   = this_blocks * block_size

        local data = get_chunk(cur_lba - start_lba, this_bytes) or ""
        if #data < this_bytes then
            data = data .. string.rep("\0", this_bytes - #data)
        end

        local written, werr
        if use_write12 then
            written, werr = pt:write12(cur_lba, data, block_size)
        else
            written, werr = pt:write10(cur_lba, data, block_size)
        end

        if not written then
            return false,
                string.format("写入失败于 LBA %d: %s", cur_lba, werr or "未知"),
                total_written, start_time
        end

        total_written = total_written + written
        cur_lba       = cur_lba + written

        local percent = math.floor(total_written * 100 / total_blocks)
        local elapsed = wall_clock() - start_time
        local speed   = elapsed > 0
            and total_written * block_size / elapsed / 1024 / 1024 or 0
        io.write(string.format("\r  进度: %d/%d 块 (%d%%) - %.2f MB/s",
            total_written, total_blocks, percent, speed))
        io.flush()
    end
    print()

    return true, nil, total_written, start_time
end

-- 通用验证循环
--   check_chunk: function(v_lba, actual_string, check_bytes) -> ok, reason
-- 返回: verify_errors, verify_bytes, verify_start
local function verify_chunks(pt, start_lba, total_blocks, block_size,
                              chunk_blocks, check_chunk, label)
    local verify_errors = 0
    local verify_lba    = start_lba
    local end_lba       = start_lba + total_blocks
    local verify_start  = wall_clock()
    local verify_bytes  = 0

    while verify_lba < end_lba do
        local remaining    = end_lba - verify_lba
        local check_blocks = math.min(chunk_blocks, remaining)
        local check_bytes  = check_blocks * block_size

        local actual, rerr = pt:read10(verify_lba, check_blocks, block_size)
        if not actual then
            print(string.format("\n  验证读取失败于 LBA %d: %s",
                verify_lba, rerr or "未知"))
            verify_errors = verify_errors + 1
            break
        end

        local ok, reason = check_chunk(verify_lba, actual, check_bytes)
        if not ok then
            print(string.format("\n  验证失败于 LBA %d: %s",
                verify_lba, reason or "数据不匹配"))
            verify_errors = verify_errors + 1
            if verify_errors > 3 then
                print("  错误太多，停止验证")
                break
            end
        end

        verify_lba  = verify_lba + check_blocks
        verify_bytes = verify_bytes + check_blocks * block_size
        local v_elapsed = wall_clock() - verify_start
        local v_speed   = v_elapsed > 0
            and verify_bytes / v_elapsed / 1024 / 1024 or 0
        io.write(string.format("\r  验证: %d/%d 块 (%d%%) - %.2f MB/s",
            verify_lba - start_lba, total_blocks,
            math.floor((verify_lba - start_lba) * 100 / total_blocks), v_speed))
        io.flush()
    end
    print()

    return verify_errors, verify_bytes, verify_start
end

-- ============================================================================
-- 写入功能
-- ============================================================================

-- 写入任意数据到设备（一次性整块写入，不分块；遗留接口，main 未使用）
local function write_to_device(device_path, lba, data, options)
    options = options or {}
    local use_write12 = options.use_write12 or false
    local verify      = options.verify or false

    print(string.format("\n=== 写入设备: %s ===", device_path))
    print(string.format("  起始 LBA: %d", lba))
    print(string.format("  数据长度: %d 字节", #data))

    local pt, err = ScsiPT.new(device_path)
    if not pt then return false, err end

    local cap, cap_err = pt:read_capacity_10()
    if not cap then
        pt:close()
        return false, "READ CAPACITY 失败: " .. (cap_err or "未知")
    end
    local block_size = cap.block_size
    print(string.format("  设备块大小: %d 字节", block_size))

    local num_blocks = math.ceil(#data / block_size)
    if num_blocks == 0 then
        pt:close()
        return false, "数据太小，必须至少一个块大小"
    end
    local aligned_len = num_blocks * block_size
    if aligned_len > #data then
        data = data .. string.rep("\0", aligned_len - #data)
    end

    if (lba + num_blocks) > cap.num_blocks then
        pt:close()
        return false, string.format("写入超出设备范围 (LBA %d + %d > %d)",
            lba, num_blocks, cap.num_blocks)
    end

    print(string.format("  写入块数: %d", num_blocks))

    pt:prevent_allow(true)

    local result, write_err
    if use_write12 then
        result, write_err = pt:write12(lba, data, block_size)
    else
        result, write_err = pt:write10(lba, data, block_size)
    end

    if result then
        print(string.format("  写入成功: %d 块", result))
        pt:sync_cache()

        if verify then
            print("  验证写入...")
            local read_data, read_err = pt:read10(lba, num_blocks, block_size)
            if read_data then
                if read_data == data:sub(1, num_blocks * block_size) then
                    print("  验证成功")
                else
                    print("  验证失败: 数据不匹配")
                end
            else
                print("  验证读取失败: " .. (read_err or "未知"))
            end
        end
    else
        print("  写入失败: " .. (write_err or "未知"))
    end

    pt:prevent_allow(false)
    pt:close()
    return result ~= nil
end

-- 从 lba 开始连续写 num_blocks 个零块，按 chunk 分批
-- 注意：pt 由调用方打开和关闭，本函数不再自己开设备
local function write_zero_range(pt, lba, num_blocks,
                                block_size, dev_total_blocks, options)
    options = options or {}
    local use_write12  = options.use_write12 or false
    local verify       = options.verify or false
    local chunk_blocks = options.chunk_blocks or DEF_CHUNK_BLOCKS

    print(string.format("\n=== 写零: %s ===", pt.device_path))
    print(string.format("  起始 LBA: %d", lba))
    print(string.format("  块数: %d", num_blocks))
    print(string.format("  块大小: %d 字节", block_size))
    print(string.format("  传输块大小: %d 块 (%d KB)",
        chunk_blocks, chunk_blocks * block_size / 1024))

    if lba + num_blocks > dev_total_blocks then
        return false, string.format("写入超出设备范围 (LBA %d + %d > %d)",
            lba, num_blocks, dev_total_blocks)
    end

    local zero_chunk = string.rep("\0", chunk_blocks * block_size)

    pt:prevent_allow(true)

    local zero_getter = function(offset_bytes, this_bytes)
        return zero_chunk:sub(1, this_bytes)
    end

    local ok, werr, total_written, start_time = write_chunks(
        pt, lba, num_blocks, block_size, chunk_blocks,
        use_write12, zero_getter, "写零")

    if not ok then
        pt:prevent_allow(false)
        return false, werr
    end

    print("  同步缓存...")
    pt:sync_cache()

    if verify then
        print("  验证中（读回对比零）...")
        local function check_zero(v_lba, actual, check_bytes)
            local p = ffi.cast("const UCHAR*", actual)
            for i = 0, check_bytes - 1 do
                if p[i] ~= 0 then
                    return false, "存在非零字节"
                end
            end
            return true
        end
        local v_errs, v_bytes, v_start = verify_chunks(
            pt, lba, num_blocks, block_size, chunk_blocks,
            check_zero, "写零")

        if v_errs == 0 then
            local v_elapsed = wall_clock() - v_start
            print(string.format("  [OK] 验证成功：全部为零 (读 %.2f MB, 耗时 %.2f 秒, %.2f MB/s)",
                v_bytes / 1024 / 1024, v_elapsed,
                v_elapsed > 0 and v_bytes / v_elapsed / 1024 / 1024 or 0))
        else
            print(string.format("  [错误] 验证有 %d 个错误", v_errs))
        end
    end

    pt:prevent_allow(false)

    local total_elapsed = wall_clock() - start_time
    print(string.format("\n  [OK] 完成！共写入 %d 块 (%.2f MB)，耗时 %.2f 秒",
        total_written,
        total_written * block_size / 1024 / 1024,
        total_elapsed))
    return true
end

-- ============================================================================
-- 盘符 / SCSI 路径枚举
-- ============================================================================

local function enumerate_cdrom_drives()
    local result = {}
    local buf = ffi.new("char[512]")
    local len = ffi.C.GetLogicalDriveStringsA(512, buf)
    if len == 0 then return result end

    local DRIVE_CDROM = 5
    local p = 0
    while p < len - 1 do
        local drive = ffi.string(buf + p)
        if #drive == 0 then break end
        p = p + #drive + 1

        if ffi.C.GetDriveTypeA(drive) == DRIVE_CDROM then
            local label_buf = ffi.new("char[256]")
            local fs_buf    = ffi.new("char[256]")
            ffi.C.GetVolumeInformationA(drive,
                label_buf, 256, nil, nil, nil, fs_buf, 256)

            local scsi_path = nil
            local dosdev_buf = ffi.new("char[512]")
            local drive_letter = drive:gsub("\\$", "")
            if ffi.C.QueryDosDeviceA(drive_letter, dosdev_buf, 512) > 0 then
                local dev_name = ffi.string(dosdev_buf):match("\\Device\\(.+)$")
                if dev_name then
                    scsi_path = "\\\\.\\" .. dev_name:upper()
                end
            end

            result[#result + 1] = {
                drive     = drive,
                label     = ffi.string(label_buf),
                fs        = ffi.string(fs_buf),
                scsi_path = scsi_path,
            }
        end
    end
    return result
end

local function find_drive_for_scsi(scsi_path, drives)
    if not scsi_path then return nil end
    local target = scsi_path:upper()
    for _, d in ipairs(drives) do
        if d.scsi_path == target then return d end
    end
    return nil
end

local function probe_pdt(path)
    local pt = ScsiPT.new(path)
    if not pt then return nil end
    local inq = pt:inquiry(false, 0, 36)
    pt:close()
    if not inq then return nil end
    return bit.band(inq:byte(1), 0x1F)
end

-- ============================================================================
-- 设备枚举
-- ============================================================================

local function enumerate_cdroms()
    local devices, seen = {}, {}
    local access = bit.bor(GENERIC_READ, GENERIC_WRITE)
    local share  = bit.bor(FILE_SHARE_READ, FILE_SHARE_WRITE)

    local function try_add(path)
        if seen[path] then return false end
        local h = ffi.C.CreateFileA(path, access, share, nil,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nil)
        if h == INVALID_HANDLE_VALUE then return false end
        ffi.C.CloseHandle(h)
        seen[path] = true
        devices[#devices + 1] = path
        return true
    end

    for i = 0, 15 do
        try_add(string.format("\\\\.\\CDROM%d", i))
    end

    for i = 0, 7 do
        local path = string.format("\\\\.\\PhysicalDrive%d", i)
        if not seen[path] then
            local pdt = probe_pdt(path)
            if pdt == 5 then
                seen[path] = true
                devices[#devices + 1] = path
            end
        end
    end

    return devices
end

-- ============================================================================
-- 设备信息显示
-- ============================================================================

local PDT_NAMES = {
    [0x00] = "Direct Access (Disk)",
    [0x01] = "Sequential Access (Tape)",
    [0x02] = "Printer",
    [0x03] = "Processor",
    [0x04] = "Write Once (WORM)",
    [0x05] = "CD/DVD (MMC)",
    [0x06] = "Scanner",
    [0x07] = "Optical Memory",
    [0x08] = "Medium Changer",
    [0x09] = "Communications",
    [0x0A] = "Graphics Arts",
    [0x0B] = "Graphics Arts",
    [0x0C] = "Storage Array",
    [0x0D] = "Enclosure",
    [0x0E] = "Simplified Disk",
    [0x0F] = "Optical Card",
    [0x10] = "Bridge Controller",
    [0x11] = "Object Storage",
    [0x12] = "Automation",
    [0x13] = "Security",
    [0x1E] = "Well Known LU",
    [0x1F] = "No Device",
}

local function get_pdt_name(pdt)
    return PDT_NAMES[pdt] or string.format("Unknown (0x%02X)", pdt)
end

local function show_device_info(device_path, drives)
    print(string.format("\n=== 设备: %s ===", device_path))

    local drv_info = find_drive_for_scsi(device_path, drives or {})
    if drv_info then
        print(string.format("  盘符: %s", drv_info.drive))
        print(string.format("  卷标: %s",
            drv_info.label ~= "" and drv_info.label or "(无)"))
        print(string.format("  文件系统: %s",
            drv_info.fs ~= "" and drv_info.fs or "(无)"))
    else
        print("  盘符: (未挂载或未识别)")
    end

    local pt, err = ScsiPT.new(device_path)
    if not pt then
        print("  [错误] " .. err)
        return
    end

    local inq, inq_err = pt:inquiry(false, 0, 96)
    if inq then
        -- inq 是 Lua 字符串，1 索引；原 inq[1] -> inq:byte(1)
        local pdt      = bit.band(inq:byte(1), 0x1F)
        local vendor   = inq:sub(9, 16):gsub("%s+$", "")
        local product  = inq:sub(17, 32):gsub("%s+$", "")
        local revision = inq:sub(33, 36):gsub("%s+$", "")

        print(string.format("  设备类型: %s", get_pdt_name(pdt)))
        print(string.format("  厂商: %s", vendor))
        print(string.format("  产品: %s", product))
        print(string.format("  版本: %s", revision))
        print(string.format("  可移动介质: %s",
            bit.band(inq:byte(2), 0x80) ~= 0 and "是" or "否"))
    else
        print("  INQUIRY 失败: " .. (inq_err or "未知"))
    end

    local cap, cap_err = pt:read_capacity_10()
    if cap then
        print(string.format("  块大小: %d 字节", cap.block_size))
        print(string.format("  总块数: %d", cap.num_blocks))
        print(string.format("  总容量: %.2f MB",
            cap.num_blocks * cap.block_size / 1024 / 1024))
    else
        print("  READ CAPACITY 失败: " .. (cap_err or "未知"))
    end

    local mode = pt:mode_sense10(0x3F)
    if mode then
        -- mode 是 Lua 字符串；原 mode[3] -> mode:byte(3)
        print(string.format("  写保护: %s",
            bit.band(mode:byte(3), 0x80) ~= 0 and "是" or "否"))
    end

    pt:close()
end

-- ============================================================================
-- 设备路径归一化
-- ============================================================================

local function normalize_device_path(input)
    if not input or input == "" then return nil end
    if input:sub(1, 4) == "\\\\.\\" or input:sub(1, 4) == "\\\\?\\" then
        return input
    end
    local upper = input:upper()
    if upper:match("^%d+$") then
        return "\\\\.\\CDROM" .. upper
    end
    if upper:match("^CDROM%d+$") then
        return "\\\\.\\" .. upper
    end
    if upper:match("^[A-Z]:?$") then
        return "\\\\.\\" .. upper:sub(1, 1) .. ":"
    end
    return input
end

-- ============================================================================
-- 主程序
-- ============================================================================

local function print_usage()
    print([[用法: luajit main.lua <命令> [参数...]

命令:
  list                              列出所有 CD-ROM 设备
  info <设备>                       显示设备详细信息
  writezero <设备> <LBA> <块数|all> 写入零数据 (all = 从 LBA 清到末尾)
  writeiso <设备> <ISO文件>         从 LBA 0 开始写入整个 ISO 文件

设备参数:
  可以直接用短名字，脚本会自动补全为 Windows 设备路径:
    0         → \\.\CDROM0
    1         → \\.\CDROM1
    CDROM0    → \\.\CDROM0
    E         → \\.\E:
    \\.\CDROM0 → \\.\CDROM0  (原样)

选项:
  --write12             使用 WRITE(12) 命令
  --verify              写入后读回验证
  --chunk=块数          每次 SCSI 传输的块数 (不指定则自动探测)

关于 --chunk:
  不指定时自动探测设备支持的最大传输块数 (带缓存)
  探测失败回退到默认 32 块 (64KB)
  USB2.0 虚拟光驱常见上限约 64KB  (chunk=32)
  USB3.0 虚拟光驱常见上限约 512KB (chunk=256)
  超过上限会返回 Error 87 (ERROR_INVALID_PARAMETER)

示例:
  luajit main.lua list
  luajit main.lua info 0
  luajit main.lua writezero 0 0 all            ; 清空整个设备
  luajit main.lua writezero 0 0 all --verify   ; 清空并验证
  luajit main.lua writeiso 0 image.iso --verify; 写入镜像
  luajit main.lua writeiso 0 image.iso --chunk=32 --verify ; 写入并验证
]])
end

local function main(args)
    if #args < 1 then
        print_usage()
        return 1
    end

    if #args >= 2 and (args[1] == "info" or args[1] == "writezero" or args[1] == "writeiso") then
        args[2] = normalize_device_path(args[2])
    end

    local command = args[1]

    if command == "list" then
        print("=== 枚举 CD-ROM 设备 ===")
        local devices = enumerate_cdroms()

        if #devices == 0 then
            print("未找到 CD-ROM 设备")
            print("提示: 需要管理员权限才能访问设备")
            return 1
        end

        local drives = enumerate_cdrom_drives()

        print(string.format("找到 %d 个设备:\n", #devices))
        for _, dev in ipairs(devices) do
            show_device_info(dev, drives)
        end

    elseif command == "info" then
        if #args < 2 then
            print("[错误] 需要指定设备路径")
            return 1
        end
        show_device_info(args[2], enumerate_cdrom_drives())

    elseif command == "writeiso" then
        if #args < 3 then
            print("[错误] 需要 设备路径 和 ISO 文件")
            print("用法: luajit main.lua writeiso <设备> <iso文件> [--verify] [--chunk=N] [--write12]")
            return 1
        end

        local device_path = args[2]
        local iso_path    = args[3]
        local opt         = parse_options(args, 4)

        local iso_file = io.open(iso_path, "rb")
        if not iso_file then
            print("[错误] 无法打开 ISO 文件 " .. iso_path)
            return 1
        end

        local iso_size = iso_file:seek("end")
        iso_file:seek("set", 0)

        print(string.format("\n=== 写入 ISO 到设备: %s ===", device_path))
        print(string.format("  ISO 文件: %s", iso_path))
        print(string.format("  ISO 大小: %d 字节 (%.2f MB)",
            iso_size, iso_size / 1024 / 1024))

        local pt, err = ScsiPT.new(device_path)
        if not pt then
            iso_file:close()
            print("  [错误] " .. err)
            return 1
        end

        local cap, cap_err = pt:read_capacity_10()
        if not cap then
            pt:close(); iso_file:close()
            print("  [错误] 无法读取设备容量: " .. (cap_err or "未知"))
            return 1
        end

        local block_size = cap.block_size
        print(string.format("  设备块大小: %d 字节", block_size))
        print(string.format("  设备总块数: %d (%.2f MB)",
            cap.num_blocks, cap.num_blocks * block_size / 1024 / 1024))

        if block_size ~= 2048 then
            pt:close(); iso_file:close()
            print(string.format("  [错误] 设备块大小是 %d，ISO 需要 2048", block_size))
            return 1
        end

        -- 解析 chunk（用户指定 or 探测），复用已打开的 pt
        local chunk_blocks = resolve_chunk(device_path, block_size, opt.chunk, pt)

        local iso_blocks = math.ceil(iso_size / block_size)
        print(string.format("  需要写入块数: %d", iso_blocks))

        if iso_blocks > cap.num_blocks then
            pt:close(); iso_file:close()
            print(string.format("  [错误] ISO 太大 (%d 块 > 设备容量 %d 块)",
                iso_blocks, cap.num_blocks))
            return 1
        end

        pt:prevent_allow(true)

        -- 写入循环：用 iso_getter 从 iso_file 顺序读取
        local iso_getter = function(offset_bytes, this_bytes)
            local data = iso_file:read(this_bytes)
            return data or ""
        end

        local ok, werr, total_written, start_time = write_chunks(
            pt, 0, iso_blocks, block_size, chunk_blocks,
            opt.use_write12, iso_getter, "写入")

        if not ok then
            print(string.format("\n  [错误] %s", werr))
            pt:prevent_allow(false)
            pt:close(); iso_file:close()
            return 1
        end

        print("  同步缓存...")
        pt:sync_cache()

        if opt.verify then
            print("  验证中（读取整个 ISO 对比）...")
            iso_file:seek("set", 0)
            local function check_iso(v_lba, actual, check_bytes)
                local expected = iso_file:read(check_bytes)
                if not expected or #expected < check_bytes then
                    expected = (expected or "") ..
                        string.rep("\0", check_bytes - #(expected or ""))
                end
                if actual == expected then
                    return true
                end
                return false, "数据不匹配"
            end
            local v_errs, v_bytes, v_start = verify_chunks(
                pt, 0, iso_blocks, block_size, chunk_blocks,
                check_iso, "验证")

            if v_errs == 0 then
                local v_elapsed = wall_clock() - v_start
                print(string.format("  [OK] 验证成功：所有数据匹配 (读 %.2f MB, 耗时 %.2f 秒, %.2f MB/s)",
                    v_bytes / 1024 / 1024, v_elapsed,
                    v_elapsed > 0 and v_bytes / v_elapsed / 1024 / 1024 or 0))
            else
                print(string.format("  [错误] 验证有 %d 个错误", v_errs))
            end
        end

        pt:prevent_allow(false)
        pt:close()
        iso_file:close()

        local total_elapsed = wall_clock() - start_time
        print(string.format("\n  [OK] 完成！共写入 %d 块 (%.2f MB)，耗时 %.2f 秒",
            total_written,
            total_written * block_size / 1024 / 1024,
            total_elapsed))

    elseif command == "writezero" then
        if #args < 4 then
            print("[错误] 需要指定设备路径、LBA 和块数（或 all）")
            print("用法: luajit main.lua writezero <设备> <LBA> <块数|all> [--write12] [--verify] [--chunk=N]")
            return 1
        end

        local device_path = args[2]
        local lba         = tonumber(args[3])
        local count_arg   = args[4]

        if not lba or lba < 0 then
            print("[错误] 起始 LBA 无效: " .. tostring(args[3]))
            return 1
        end

        local opt = parse_options(args, 5)

        -- 复用同一个 pt：探测 / 写入 / 验证都在这一个句柄上做
        local pt = ScsiPT.new(device_path)
        if not pt then
            print("写入失败: 无法打开设备 " .. device_path)
            return 1
        end

        local cap, cap_err = pt:read_capacity_10()
        if not cap then
            pt:close()
            print("写入失败: READ CAPACITY 失败: " .. (cap_err or "未知"))
            return 1
        end

        local block_size = cap.block_size

        -- 解析块数
        local num_blocks
        if type(count_arg) == "string" and count_arg:lower() == "all" then
            num_blocks = cap.num_blocks - lba
            if num_blocks <= 0 then
                pt:close()
                print(string.format("[错误] 起始 LBA %d 超出设备范围 (总块数 %d)",
                    lba, cap.num_blocks))
                return 1
            end
            print(string.format("模式: 清空全部 (LBA %d 到 %d, 共 %d 块 = %.2f MB)",
                lba, cap.num_blocks - 1, num_blocks,
                num_blocks * block_size / 1024 / 1024))
        else
            num_blocks = tonumber(count_arg)
            if not num_blocks or num_blocks <= 0 then
                pt:close()
                print("[错误] 块数无效: " .. tostring(count_arg))
                return 1
            end
        end

        -- 解析 chunk（用户指定 or 探测），复用已打开的 pt
        opt.chunk_blocks = resolve_chunk(device_path, block_size, opt.chunk, pt)

        local ok, err = write_zero_range(
            pt, lba, num_blocks, block_size, cap.num_blocks, opt)
        pt:close()
        if not ok then
            print("  [错误] " .. (err or "未知错误"))
            return 1
        end

    else
        print("未知命令: " .. command)
        print_usage()
        return 1
    end

    return 0
end

local exit_code = main({...})
os.exit(exit_code)
