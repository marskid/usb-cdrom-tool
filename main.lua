-- ============================================
-- 编码：GB2312
-- U盘ISO更新程序 1.4
-- IUP 图形界面 + Windows SCSI Pass-Through Direct (SPTI)
-- ============================================

-- Copyright (C) 2026  marskid

-- This file is part of U盘ISO更新程序.

-- U盘ISO更新程序 is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.

-- U盘ISO更新程序 is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.

-- You should have received a copy of the GNU General Public License
-- along with U盘ISO更新程序.  If not, see <https://www.gnu.org/licenses/>.

local iup = require "iuplua"
require "iupluacontrols"

local ffi = require("ffi")
local bit = require("bit")

local FONT = "Microsoft YaHei, 9"

local APP_NAME    = "U盘ISO更新程序"
local APP_VERSION = "1.4"
local APP_YEAR    = "2026"
local APP_AUTHOR  = "marskid"
local APP_GITHUB  = "https://github.com/marskid/usb-cdrom-tool"
local APP_COPYRIGHT   = string.format([[
%s 版本 %s
Copyright (C) %s %s

本程序是自由软件：你可以根据自由软件基金会发布的 GNU 通用公共许可证
（许可证第 3 版，或你选择的任何更新版本）重新分发和/或修改它。

本程序的发布是希望它能有用，但没有任何担保；甚至没有适销性或特定用途
适用性的默示担保。详情请参阅 GNU 通用公共许可证。

你应该已随本程序收到一份 GNU 通用公共许可证的副本。如果没有，请访问
 <https://www.gnu.org/licenses/>。

注意：本程序涉及磁盘操作，可能造成数据丢失甚至损坏设备。作者已明确声
明不承担任何因使用本程序导致的直接或间接损失。
]], APP_NAME, APP_VERSION, APP_YEAR, APP_AUTHOR)

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
    self.sptd            = ffi.new("SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER")
    self.bytes_returned  = ffi.new("DWORD[1]")
    self.data_buf        = nil
    self.data_buf_size   = 0
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
-- chunk 探测（logfn 用于把日志送到 GUI；缺省走 print）
-- ============================================================================

local function resolve_chunk(device_path, block_size, user_chunk, pt, logfn)
    logfn = logfn or print
    if user_chunk then
        logfn(string.format("  手动指定 chunk: %d 块 (%d KB)",
            user_chunk, user_chunk * block_size / 1024))
        return user_chunk
    end

    local cached = PROBED_CHUNK[device_path]
    if cached then
        logfn(string.format("  使用探测缓存: %d 块 (%d KB)",
            cached, cached * block_size / 1024))
        return cached
    end

    local owns_pt = false
    if not pt then
        pt = ScsiPT.new(device_path)
        if not pt then
            logfn(string.format("  [警告] 探测打开设备失败，使用默认 %d 块", DEF_CHUNK_BLOCKS))
            return DEF_CHUNK_BLOCKS
        end
        owns_pt = true
    end

    local n = pt:probe_max_chunk(block_size, 0)
    local last_err = pt.probe_last_err
    if owns_pt then pt:close() end

    if n then
        logfn(string.format("  探测到最大传输: %d 块 (%d KB)",
            n, n * block_size / 1024))
        return n
    end

    local first_line = ""
    if last_err then
        first_line = last_err:match("^([^\n]+)") or ""
    end
    if first_line ~= "" then
        first_line = " (" .. first_line .. ")"
    end
    logfn(string.format("  [警告] 探测失败%s，使用默认 %d 块 (%d KB)",
        first_line, DEF_CHUNK_BLOCKS, DEF_CHUNK_BLOCKS * block_size / 1024))
    return DEF_CHUNK_BLOCKS
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
-- 日志控件
-- ============================================================================

local log_box = iup.multiline {
    multiline = "YES",
    readonly = "YES",
    scrollbar = "YES",
    font = "Consolas, 9",
    value = "",
    size = "x80",
    visible = "NO",
    expand = "YES",
}

local log_visible = false

local function log(msg)
    -- IUP multiline 的 append 自带换行，不要再追加 "\n"（否则每条多一空行）
    log_box.append = msg
    log_box.caretpos = #log_box.value   -- 自动滚到底部
end

-- ============================================================================
-- 顶部控件
-- ============================================================================

local dropdown = iup.list {
    dropdown = "YES",
    font = FONT,
    expand = "HORIZONTAL",
    "（请先扫描设备）",
}

local BTN_W = "62x15"

local btn_scan = iup.button {
    title = "扫描U盘",
    font = FONT,
    size = BTN_W,
}

local btn_iso = iup.button {
    title = "选择ISO",
    font = FONT,
    size = BTN_W,
}

local btn_update = iup.button {
    title = "更新U盘",
    font = FONT,
    size = BTN_W,
}

local btn_toggle_log = iup.button {
    title = "显示日志",
    font = FONT,
    size = BTN_W,
}

-- 日志面板默认隐藏，仅在出错时由调用方主动展开（dlg 在下方创建，调用时一定已就绪）
local function show_log()
    if not log_visible then
        log_visible = true
        log_box.visible = "YES"
        btn_toggle_log.title = "隐藏日志"
        dlg.size = "415x200"
        dlg:show()
        iup.Update(log_box)
        log_box.caretpos = #log_box.value   -- 展开后滚动到最新一行
    end
end

local file_path = iup.text {
    expand = "HORIZONTAL",
    font = FONT,
    value = "",
    readonly = "YES",
    canfocus = "NO",   -- 纯展示用途，禁止获得焦点（避免只读框里闪烁的插入符）
    size = "x12",
}

local progress = iup.progressbar {
    min = 0,
    max = 100,
    value = 0,
    size = "x12",
    expand = "HORIZONTAL",
}

-- 写入后读回与 ISO 逐块比对（默认开启）
local chk_verify = iup.toggle {
    title = "写入后校验",
    font = FONT,
    value = "ON",
    canfocus = "NO",
}

-- ============================================================================
-- 底部信息区（数值标签保留引用，供刷新）
-- ============================================================================

-- 注意：label 创建后再改 title 不会重算自然宽度，必须按实测像素给固定宽度
-- （YaHei 9：无介质=54 / 670.3M=43 / 20.0M/s=47 / 100%=32）
local part_val = iup.label { title = "--", font = FONT, alignment = "ALEFT", size = "54x" }
local iso_val  = iup.label { title = "--", font = FONT, alignment = "ALEFT", size = "44x" }
local speed_val = iup.label { title = "--", font = FONT, alignment = "ALEFT", size = "48x" }
local pct_label = iup.label { title = "0%", font = FONT, alignment = "ALEFT", size = "33x" }

local bottom_row = iup.hbox {
    iup.label { title = "分区：", font = FONT },
    part_val,
    iup.label { title = "ISO：", font = FONT },
    iso_val,
    iup.label { title = "速度：", font = FONT },
    speed_val,
    pct_label,
    iup.fill {},
    btn_toggle_log,
    gap = "2",
    alignment = "ACENTER",
    expand = "HORIZONTAL",
}

local status_label = iup.label {
    title = "1、扫描U盘，2、选择ISO，3、更新U盘",
    font = FONT,
    alignment = "ALEFT",
    expand = "HORIZONTAL",
}

-- ============================================================================
-- 设备列表与写入状态
-- ============================================================================

-- dev_list[i] = {
--   path=SCSI路径, drive="E:\\"|nil, label=卷标,
--   cap=READ CAPACITY 结果或 nil(无介质), wp=bool,
--   vendor/product/revision=string
-- }
local dev_list = {}

-- 写入状态机上下文；nil = 当前没有写入任务
-- worker = { pt, iso_file, cur, total, written, chunk, bs, start, abort,
--            phase="write"|"verify", do_verify, v_cur, v_errors, v_start }
local worker = nil

local function set_busy(busy)
    local state = busy and "NO" or "YES"
    btn_scan.active   = state
    btn_iso.active    = state
    dropdown.active   = state
    chk_verify.active = state
    -- btn_update 写入/校验期间保持可用：它此时承担"中止"按钮
end

-- 下拉框动态增删
local function list_clear(lst)
    local n = tonumber(lst.count) or 0
    for i = n, 1, -1 do
        lst.removeitem = tostring(i)
    end
end

local function dev_display_name(e)
    if e.drive and e.drive ~= "" then
        return e.drive:gsub("\\$", "")           -- "E:\\" -> "E:"
    end
    return (e.path:gsub("^\\+%.\\", ""))          -- "\\.\CDROM0" -> "CDROM0"
end

local function dev_cap_text(e)
    if not e.cap then return "无介质" end
    local mb = e.cap.num_blocks * e.cap.block_size / 1048576
    if mb >= 1024 then
        return string.format("%.1fG", mb / 1024)
    end
    return string.format("%dM", math.floor(mb))
end

local function dev_dropdown_text(e)
    local label = e.label
    if not label or label == "" then label = e.product or "" end
    if not label or label == "" then label = "无卷标" end
    return string.format("%s %s %s", dev_display_name(e), dev_cap_text(e), label)
end

local function show_selected_dev_info()
    local idx = tonumber(dropdown.value)
    local e = idx and dev_list[idx]
    if e and e.cap then
        local mb = e.cap.num_blocks * e.cap.block_size / 1048576
        if mb >= 1024 then
            part_val.title = string.format("%.2fG", mb / 1024)
        else
            part_val.title = string.format("%dM", math.floor(mb + 0.5))
        end
    elseif e then
        part_val.title = "无介质"
    else
        part_val.title = "--"
    end
end

-- 下拉选择变化
function dropdown:action(text, item, state)
    if state == 1 then
        show_selected_dev_info()
    end
    return iup.DEFAULT
end

-- ============================================================================
-- 扫描（按钮和下拉框展开时共用）
-- ============================================================================

local scanning = false
local has_scanned = false      -- 程序启动后是否执行过至少一次扫描

local function do_scan()
    -- 防止重入（iup.Update 刷新期间再次触发）
    if scanning then return end
    scanning = true
    has_scanned = true

    status_label.title = "正在扫描CD-ROM设备..."
    log("[INFO] 开始扫描 CD-ROM 设备...")
    iup.Update(dlg)

    local paths = enumerate_cdroms()
    local drives = enumerate_cdrom_drives()

    dev_list = {}
    local texts = {}

    for _, path in ipairs(paths) do
        local e = {
            path  = path,
            label = "",
        }
        local drv = find_drive_for_scsi(path, drives)
        if drv then
            e.drive = drv.drive
            e.label = drv.label or ""
        end

        local pt = ScsiPT.new(path)
        if pt then
            local inq = pt:inquiry(false, 0, 96)
            if inq then
                e.vendor   = inq:sub(9, 16):gsub("%s+$", "")
                e.product  = inq:sub(17, 32):gsub("%s+$", "")
                e.revision = inq:sub(33, 36):gsub("%s+$", "")
            end
            local cap = pt:read_capacity_10()
            e.cap = cap or nil
            if not cap then
                log(string.format("[WARN] %s READ CAPACITY 失败（可能未放盘）", path))
            end
            local mode = pt:mode_sense10(0x3F)
            if mode then
                e.wp = bit.band(mode:byte(3), 0x80) ~= 0
            end
            pt:close()
        else
            log("[ERROR] 无法打开设备 " .. path)
        end

        dev_list[#dev_list + 1] = e
        texts[#texts + 1] = dev_dropdown_text(e)

        log(string.format("[INFO] 发现设备: %s [%s] %s %s, 块大小=%s%s",
            path,
            e.vendor or "?",
            e.product or "?",
            e.revision or "",
            e.cap and tostring(e.cap.block_size) or "?",
            e.wp and ", 写保护" or ""))
    end

    list_clear(dropdown)
    if #texts == 0 then
        dropdown[1] = "（未找到设备）"
        dropdown.value = "1"
        part_val.title = "--"
        status_label.title = "未找到 CD-ROM 设备（需要管理员权限）"
        log("[WARN] 未找到 CD-ROM 设备，提示：需要管理员权限才能访问设备")
    else
        for i, t in ipairs(texts) do
            dropdown[i] = t
        end
        dropdown.value = "1"
        show_selected_dev_info()
        status_label.title = string.format("找到 %d 个设备，请选择ISO文件", #dev_list)
        log(string.format("[INFO] 扫描完成，共 %d 个设备。", #dev_list))
    end

    scanning = false
end

function btn_scan:action()
    do_scan()
    return iup.DEFAULT
end

-- 仅在程序启动后从未扫描过（下拉框为空）时，点开下拉框自动扫描一次；
-- 之后刷新设备一律由"扫描U盘"按钮负责，避免选中/取消选中时重复扫描。
function dropdown:dropdown_cb()
    if not has_scanned and not worker then
        do_scan()
    end
    return iup.DEFAULT
end

-- ============================================================================
-- 选择 ISO 按钮
-- ============================================================================

function btn_iso:action()
    local filedlg = iup.filedlg {
        dialogtype = "OPEN",
        title = "选择ISO文件",
        filter = "*.iso",
        filterinfo = "ISO 文件 (*.iso)",
    }
    filedlg:popup(iup.CENTER, iup.CENTER)
    if filedlg.status == "0" then
        local path = filedlg.value
        if path and path ~= "" then
            file_path.value = path
            local f = io.open(path, "rb")
            if f then
                local sz = f:seek("end")
                f:close()
                local imb = sz / 1048576
                iso_val.title = imb >= 1024
                    and string.format("%.2fG", imb / 1024)
                    or string.format("%.1fM", imb)
                log("[INFO] 已选择ISO: " .. path ..
                    string.format(" (%.2f MB)", sz / 1048576))
                status_label.title = "ISO已选择，可以开始更新U盘"
            else
                log("[ERROR] 无法读取 ISO 文件大小: " .. path)
            end
        end
    else
        log("[INFO] 已取消ISO选择。")
    end
    filedlg:destroy()
    return iup.DEFAULT
end

-- ============================================================================
-- 写入状态机（timer 驱动）
-- ============================================================================

local timer = iup.timer { time = 50, run = "NO" }

-- result:
--   "ok"          写入完成（未勾选校验）
--   "verified"    写入 + 读回校验全部通过
--   "verify_fail" 写入完成但校验发现不一致
--   "vabort"      写入已完成，校验被用户中止
--   "abort"       写入阶段被用户中止
--   "error"       写入或校验读取出错
local function finish_write(result, err)
    timer.run = "NO"
    local w = worker
    worker = nil
    if not w then return end

    local mb = w.total * w.bs / 1048576

    if result == "abort" then
        -- 写入阶段中止：不执行 SYNCHRONIZE CACHE，直接收尾
        log(string.format("[WARN] 写入已被用户中止：已写 %d/%d 块 (%d%%)",
            w.written, w.total,
            w.total > 0 and math.floor(w.written * 100 / w.total) or 0))
    elseif result == "error" then
        log("[ERROR] 更新失败:")
        log(err or "未知错误")
    else
        -- 数据已完整写入并在阶段切换前同步过缓存
        local elapsed = wall_clock() - w.start
        log(string.format("[INFO] 写入完成：共写入 %d 块 (%.2f MB)，耗时 %.2f 秒，平均 %.2f MB/s",
            w.total, mb, elapsed,
            elapsed > 0 and mb / elapsed or 0))

        if result == "verified" then
            local velapsed = wall_clock() - w.v_start
            log(string.format("[INFO] 校验通过：全部 %d 块与 ISO 一致，读回耗时 %.2f 秒，平均 %.2f MB/s",
                w.total, velapsed,
                velapsed > 0 and mb / velapsed or 0))
        elseif result == "vabort" then
            log(string.format("[WARN] 校验已被用户中止：已校验 %d/%d 块 (%d%%)",
                w.v_cur, w.total,
                w.total > 0 and math.floor(w.v_cur * 100 / w.total) or 0))
        elseif result == "verify_fail" then
            log(string.format("[ERROR] 校验发现 %d 处数据不一致", w.v_errors))
        end
    end

    pcall(function() w.pt:prevent_allow(false) end)
    w.pt:close()
    w.iso_file:close()

    set_busy(false)
    btn_update.title = "更新U盘"
    btn_update.active = "YES"

    if result == "ok" or result == "verified" then
        progress.value = 100
        pct_label.title = "100%"
        status_label.title = result == "verified" and "更新完成（已校验）" or "更新完成"
    elseif result == "vabort" then
        status_label.title = "更新完成（校验已中止）"
    elseif result == "abort" then
        status_label.title = "写入已中止"
    else
        status_label.title = "更新失败，请查看日志"
        show_log()
    end
end

-- 写入阶段完成：同步缓存，然后切换到校验阶段或直接收尾
local function write_phase_done(w)
    log("[INFO] 数据写入完成，正在同步缓存...")
    iup.Update(dlg)
    local sok, serr = w.pt:sync_cache()
    if not sok then
        log("[WARN] SYNCHRONIZE CACHE 返回错误（部分设备不支持，可忽略）:")
        log(serr or "未知")
    end

    -- 同步期间用户点了中止：写入已完成，跳过校验
    if w.abort or not w.do_verify then
        finish_write(w.abort and "vabort" or "ok")
        return
    end

    -- 进入校验阶段：进度条从 0 重新开始
    w.phase    = "verify"
    w.v_cur    = 0
    w.v_errors = 0
    w.v_start  = wall_clock()
    w.iso_file:seek("set", 0)

    progress.value = 0
    pct_label.title = "0%"
    speed_val.title = "--"
    status_label.title = "正在校验：0%"
    log("[INFO] 开始读回校验...")
end

function timer:action_cb()
    local w = worker
    if not w then
        timer.run = "NO"
        return iup.DEFAULT
    end

    -- 每次 tick 突发处理约 250ms 再回消息循环：
    -- 既不受定时器最小间隔限速，又能保持界面刷新（写入/校验两阶段同理）
    local burst_start = wall_clock()

    if w.phase == "write" then
        while w.cur < w.total do
            if w.abort then break end

            local this_blocks = math.min(w.chunk, w.total - w.cur)
            local this_bytes  = this_blocks * w.bs

            local data = w.iso_file:read(this_bytes) or ""
            if #data < this_bytes then
                data = data .. string.rep("\0", this_bytes - #data)
            end

            local written, werr = w.pt:write10(w.cur, data, w.bs)
            if not written then
                finish_write("error",
                    string.format("写入失败于 LBA %d: %s", w.cur, werr or "未知"))
                return iup.DEFAULT
            end

            w.cur     = w.cur + written
            w.written = w.written + written

            if wall_clock() - burst_start >= 0.25 then
                break
            end
        end

        -- 全部写完优先于中止标志（最后一块写完的同一 tick 里用户点了中止）
        if w.cur >= w.total then
            write_phase_done(w)
            return iup.DEFAULT
        end
        if w.abort then
            finish_write("abort")
            return iup.DEFAULT
        end

        local percent = math.floor(w.written * 100 / w.total)
        local elapsed = wall_clock() - w.start
        local speed   = elapsed > 0
            and w.written * w.bs / elapsed / 1048576 or 0

        progress.value = percent
        pct_label.title = percent .. "%"
        speed_val.title = string.format("%.1fM/s", speed)
        status_label.title = string.format("正在写入：%d/%d 块 (%d%%)",
            w.written, w.total, percent)
        log(string.format("[PROGRESS] %d%%  %d/%d 块  %.2f MB/s",
            percent, w.written, w.total, speed))

    elseif w.phase == "verify" then
        while w.v_cur < w.total do
            if w.abort then break end

            local this_blocks = math.min(w.chunk, w.total - w.v_cur)
            local this_bytes  = this_blocks * w.bs

            local actual, rerr = w.pt:read10(w.v_cur, this_blocks, w.bs)
            if not actual then
                finish_write("error",
                    string.format("校验读取失败于 LBA %d: %s", w.v_cur, rerr or "未知"))
                return iup.DEFAULT
            end

            local expected = w.iso_file:read(this_bytes)
            if not expected or #expected < this_bytes then
                expected = (expected or "") ..
                    string.rep("\0", this_bytes - #(expected or ""))
            end

            if actual ~= expected then
                w.v_errors = w.v_errors + 1
                log(string.format("[ERROR] 校验失败于 LBA %d：数据与 ISO 不一致", w.v_cur))
                if w.v_errors > 3 then
                    finish_write("verify_fail")
                    return iup.DEFAULT
                end
            end

            w.v_cur = w.v_cur + this_blocks

            if wall_clock() - burst_start >= 0.25 then
                break
            end
        end

        if w.abort then
            finish_write("vabort")
            return iup.DEFAULT
        end

        local percent = math.floor(w.v_cur * 100 / w.total)
        local elapsed = wall_clock() - w.v_start
        local speed   = elapsed > 0
            and w.v_cur * w.bs / elapsed / 1048576 or 0

        progress.value = percent
        pct_label.title = percent .. "%"
        speed_val.title = string.format("%.1fM/s", speed)
        status_label.title = string.format("正在校验：%d/%d 块 (%d%%)",
            w.v_cur, w.total, percent)

        if w.v_cur >= w.total then
            finish_write(w.v_errors == 0 and "verified" or "verify_fail")
        end
    end

    return iup.DEFAULT
end

-- ============================================================================
-- 更新按钮
-- ============================================================================

function btn_update:action()
    -- 写入进行中：本按钮即"中止"，点击立即请求停止（不弹确认）
    if worker then
        worker.abort = true
        btn_update.active = "NO"   -- 防止重复点击；finish_write 会统一恢复
        status_label.title = "正在中止..."
        return iup.DEFAULT
    end

    local idx = tonumber(dropdown.value)
    local dev = idx and dev_list[idx]
    if not dev then
        status_label.title = "请先扫描并选择设备"
        log("[WARN] 未选择设备。")
        return iup.DEFAULT
    end

    local iso_path = file_path.value
    if not iso_path or iso_path == "" then
        status_label.title = "请先选择ISO文件"
        log("[WARN] 未选择ISO文件。")
        return iup.DEFAULT
    end

    if not dev.cap then
        status_label.title = "设备无介质，无法写入"
        log("[ERROR] 设备 " .. dev.path .. " READ CAPACITY 不可用，无法写入。")
        show_log()
        return iup.DEFAULT
    end

    log("[INFO] 开始更新: " .. dev.path .. " <- " .. iso_path)

    local iso_file = io.open(iso_path, "rb")
    if not iso_file then
        status_label.title = "无法打开ISO文件"
        log("[ERROR] 无法打开 ISO 文件 " .. iso_path)
        show_log()
        return iup.DEFAULT
    end
    local iso_size = iso_file:seek("end")
    iso_file:seek("set", 0)

    local pt, err = ScsiPT.new(dev.path)
    if not pt then
        iso_file:close()
        status_label.title = "无法打开设备"
        log("[ERROR] " .. (err or "未知"))
        show_log()
        return iup.DEFAULT
    end

    local cap, cap_err = pt:read_capacity_10()
    if not cap then
        pt:close(); iso_file:close()
        status_label.title = "读取设备容量失败"
        log("[ERROR] READ CAPACITY 失败: " .. (cap_err or "未知"))
        show_log()
        return iup.DEFAULT
    end

    local block_size = cap.block_size
    local iso_blocks = math.ceil(iso_size / block_size)

    if block_size ~= 2048 then
        pt:close(); iso_file:close()
        status_label.title = string.format("设备块大小 %d，需要 2048", block_size)
        log(string.format("[ERROR] 设备块大小是 %d，ISO 需要 2048", block_size))
        show_log()
        return iup.DEFAULT
    end

    if iso_blocks > cap.num_blocks then
        pt:close(); iso_file:close()
        status_label.title = "ISO 大于设备容量"
        log(string.format("[ERROR] ISO 太大 (%d 块 > 设备容量 %d 块)",
            iso_blocks, cap.num_blocks))
        show_log()
        return iup.DEFAULT
    end

    local mode = pt:mode_sense10(0x3F)
    if mode and bit.band(mode:byte(3), 0x80) ~= 0 then
        pt:close(); iso_file:close()
        status_label.title = "设备写保护，无法写入"
        log("[ERROR] 设备处于写保护状态。")
        show_log()
        return iup.DEFAULT
    end

    log(string.format("[INFO] ISO 大小: %.2f MB, %d 块；设备容量: %d 块",
        iso_size / 1048576, iso_blocks, cap.num_blocks))

    local chunk_blocks = resolve_chunk(dev.path, block_size, nil, pt, log)

    worker = {
        pt        = pt,
        iso_file  = iso_file,
        cur       = 0,
        total     = iso_blocks,
        written   = 0,
        chunk     = chunk_blocks,
        bs        = block_size,
        start     = wall_clock(),
        abort     = false,
        phase     = "write",       -- "write" -> "verify"
        do_verify = chk_verify.value == "ON",
        v_cur     = 0,
        v_errors  = 0,
        v_start   = 0,
    }

    progress.value = 0
    pct_label.title = "0%"
    speed_val.title = "--"
    set_busy(true)

    -- 写入期间更新按钮变为"中止"；日志面板保持隐藏，仅出错时自动展开
    btn_update.title = "中止"
    btn_update.active = "YES"

    status_label.title = "正在写入..."
    timer.run = "YES"
    return iup.DEFAULT
end

-- ============================================================================
-- 布局
-- ============================================================================

local top_row = iup.hbox {
    iup.label { title = "CD-ROM：", font = FONT, alignment = "ARIGHT" },
    dropdown,
    iup.fill {},
    btn_scan,
    btn_iso,
    btn_update,
    gap = "8",
    alignment = "ACENTER",
}

local path_row = iup.hbox {
    iup.label { title = "文件：", font = FONT, alignment = "ARIGHT" },
    file_path,
    chk_verify,
    gap = "8",
    alignment = "ACENTER",
    expand = "HORIZONTAL",
}

local progress_row = iup.hbox {
    iup.label { title = "进度：", font = FONT, alignment = "ARIGHT" },
    progress,
    gap = "8",
    alignment = "ACENTER",
    expand = "HORIZONTAL",
}

-- 关于入口：做成无立体边框的按钮（IUP 的 label 不响应点击）
local btn_about = iup.link {
    title = "关于",
    font = FONT,
    flat = "YES",
    canfocus = "NO",
}

local status_row = iup.hbox {
    status_label,
    btn_about,
    gap = "8",
    alignment = "ACENTER",
    expand = "HORIZONTAL",
}

local content = iup.vbox {
    top_row,
    path_row,
    progress_row,
    bottom_row,
    status_row,
    log_box,
    margin = "10x5",
    expand = "YES",
}

-- ============================================================================
-- 对话框
-- ============================================================================

dlg = iup.dialog {
    title = APP_NAME .. " " .. APP_VERSION,
    content,
    resize = "NO",
    size = "415x110",
    icon = "MAINICON",
}

-- 关于窗口：版本信息（LuaJIT / IUP 版本运行时动态获取）
local function show_about()
    local btn_ok = iup.button { title = "确定", font = FONT, size = "60x", canfocus = "NO" }
    function btn_ok:action() return iup.CLOSE end

    local ab = iup.dialog {
        title = "关于",
        resize = "NO",
        PARENTDIALOG = dlg,
        icon = "MAINICON",
        iup.vbox {
            margin = "16x5",
            iup.hbox {
                iup.label { title = APP_COPYRIGHT, font = FONT },
                gap = "8",
                alignment = "ACENTER",
            },
            iup.hbox {
                iup.label { title = "项目地址:", font = FONT },
                iup.link { title = APP_GITHUB, url = APP_GITHUB, font = FONT, rastersize = "x17" },
                gap = "8",
                alignment = "ACENTER",
            },
            iup.hbox {
                iup.label { title = jit.version, font = FONT },
                iup.link { title = "https://luajit.org", url = "https://luajit.org", font = FONT, rastersize = "x17" },
                gap = "8",
                alignment = "ACENTER",
            },
            iup.hbox {
                iup.label { title = "IUP " .. iup._VERSION ..
                    " (" .. iup._VERSION_DATE .. ")", font = FONT },
                iup.link {
                    title = "https://www.tecgraf.puc-rio.br/iup/",
                    url = "https://www.tecgraf.puc-rio.br/iup/",
                    font = FONT,
                    rastersize = "x17",
                },
                gap = "8",
                alignment = "ACENTER",
            },
            iup.hbox { iup.fill {}, btn_ok },
        },
    }
    ab:popup(iup.CENTERPARENT, iup.CENTERPARENT)
    ab:destroy()
end

function btn_about:action()
    show_about()
    return iup.DEFAULT
end

function btn_toggle_log:action()
    if not log_visible then
        show_log()
    else
        log_visible = false
        log_box.visible = "NO"
        btn_toggle_log.title = "显示日志"
        dlg.size = "415x110"
        dlg:show()
    end
    return iup.DEFAULT
end

function dlg:close_cb()
    timer.run = "NO"
    return iup.CLOSE
end

-- ============================================================================
-- 启动
-- ============================================================================

dlg:show()
log("[INFO] 界面已启动（SCSI 核心已加载）。")
iup.MainLoop()
