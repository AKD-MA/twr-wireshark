-- DW TWR Protocol Dissector for Wireshark
-- Copyright (C) 2025 [AKD-MA, akdma@gmx.net]
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; either version 2 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License along
-- with this program; if not, write to the Free Software Foundation, Inc.,
-- 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
--
-- DW TWR Protocol Dissector
--
-- thanks to https://chat.mistral.ai for support.

-- define the protocol
dw_twr_proto = Proto("dw_twr", "DW TWR (UWB)")

-- message types
local dw_msg_types = {
    [0x21] = "Poll",          -- 3 Bytes: ID (0x21) + 2 weitere Bytes
    [0x10] = "Response",      -- 4 Bytes: ID (0x10), Activity (0x02), Activity Parameter (2 Bytes)
    [0x29] = "Final",         -- 
    [0x2A] = "Report",        -- 
}

-- TWR-Payload
local f = dw_twr_proto.fields
f.msg_type = ProtoField.uint8("dw_twr.msg_type", "Message Type", base.HEX, dw_msg_types)

-- Poll (0x21)
f.poll_id = ProtoField.uint8("dw_twr.poll_id", "Poll ID", base.HEX)
f.poll_data = ProtoField.uint16("dw_twr.poll_data", "Poll Data", base.HEX)

-- Response (0x10)
f.response_id = ProtoField.uint8("dw_twr.response_id", "Response ID", base.HEX)
f.activity = ProtoField.uint8("dw_twr.activity", "Activity", base.HEX)
f.activity_param = ProtoField.uint16("dw_twr.activity_param", "Activity Parameter", base.HEX)

-- Final (0x29)
f.final_p_ts = ProtoField.uint64("dw_twr.final_p_ts", "Poll Time-Stamp", base.HEX)
f.final_r_ts = ProtoField.uint64("dw_twr.final_r_ts", "Response Time-Stamp", base.HEX)
f.final_f_ts = ProtoField.uint64("dw_twr.final_f_ts", "Final Time-Stamp", base.HEX)

f.final_range = ProtoField.float("dw_twr.final_range", "Range (m)", base.DEC)

-- Report (0x2A)
f.report_data = ProtoField.uint64("dw_twr.report_data", "Report Data", base.HEX)
f.report_payload = ProtoField.bytes("dw_twr.report_data", "Report Payload")
f.report_p_ts = ProtoField.uint64("dw_twr.report_p_ts", "Poll Time-Stamp", base.HEX)
f.report_r_ts = ProtoField.uint64("dw_twr.report_r_ts", "Response Time-Stamp", base.HEX)
f.report_f_ts = ProtoField.uint64("dw_twr.report_f_ts", "Final Time-Stamp", base.HEX)

-- TOF (part of report)
f.tof_raw = ProtoField.bytes("dw_twr.tof_raw", "TOF Raw Data (5 Bytes)", base.SPACE)
f.tof_ps = ProtoField.double("dw_twr.tof_ps", "TOF (Picoseconds)", base.DEC)
f.tof_ns = ProtoField.double("dw_twr.tof_ns", "TOF (Nanoseconds)", base.DEC)
f.tof_m = ProtoField.double("dw_twr.tof_m", "TOF (Meters)", base.DEC)

-- ZigBee data
f.zb_protocol_v = ProtoField.uint8("dw_twr.zb_protocol_v", "Protokoll Version", base.DEC)
f.zb_channel = ProtoField.uint8("dw_twr.zb_channel", "Chanel ID", base.DEC)
f.zb_device_id = ProtoField.uint16("dw_twr.zb_device_id", "Device ID", base.DEC)
f.zb_sequence_no = ProtoField.uint32("dw_twr.zb_sequence_no", "Sequence Number", base.DEC)

-- IEEE data
f.ieee_source = ProtoField.uint16("dw_twr.ieee_source", "Source",base.HEX)
f.ieee_destination = ProtoField.uint16("dw_twr.ieee_destination", "Destination",base.HEX)

-- Function to convert bytes to 40 bit: 5 Bytes in 40-Bit-Value (Lua 5.2-compatible)
local function bytes_to_40bit(buffer, offset)
    local byte1 = buffer(offset, 1):uint()
    local byte2 = buffer(offset + 1, 1):uint()
    local byte3 = buffer(offset + 2, 1):uint()
    local byte4 = buffer(offset + 3, 1):uint()
    local byte5 = buffer(offset + 4, 1):uint()

    -- calculate 40-Bit-value (Little-Endian)
    return byte1 + byte2 * 256 + byte3 * 65536 + byte4 * 16777216 + byte5 * 4294967296
end

-- Dissector-Function
function dw_twr_proto.dissector(buffer, pinfo, tree)
    -- verfify minium length of data
    if buffer:len() < 41 then return false end

    pinfo.cols.protocol = dw_twr_proto.name

    local subtreeE = tree:add(dw_twr_proto, buffer(), "ZigBee Encapsulation Protocol")
    subtreeE:add(f.zb_protocol_v, buffer(2,1))
    subtreeE:add(f.zb_channel, buffer(4,1))
    subtreeE:add(f.zb_device_id, buffer(5,2))
    subtreeE:add(f.zb_sequence_no, buffer(17,4))


    local ieee_buffer = buffer(32)
    local subtreeIEEE = tree:add(dw_twr_proto, ieee_buffer(), "IEEE 802.15.4 Data")
    subtreeIEEE:add_le(f.ieee_destination, ieee_buffer(5,2))
    subtreeIEEE:add_le(f.ieee_source, ieee_buffer(7,2))


    -- length of ZigBee-Header, TWR-Payload starts at twr_offset
    local twr_offset = 41
    local twr_buffer = buffer(twr_offset)

    -- tree for TWR data
    local subtree = tree:add(dw_twr_proto, twr_buffer(), "DW TWR (UWB)")

    -- verify that TWR-Payload is there
    if twr_buffer:len() < 1 then return false end


    local msg_type = twr_buffer(0,1):uint()
    subtree:add(f.msg_type, twr_buffer(0,1))
    print(string.format("Message Type: 0x%02X", msg_type))

    -- Poll Message (0x21) is 3 Bytes long
    if msg_type == 0x21 and twr_buffer:len() >= 3 then
        subtree:add(f.poll_id, twr_buffer(0,1))
        subtree:add_le(f.poll_data, twr_buffer(1,2))
        pinfo.cols.info = string.format("Poll Message")
        return true
    end

    -- Response Message (0x10) is 4 Bytes long
    if msg_type == 0x10 and twr_buffer:len() >= 4 then
        subtree:add(f.response_id, twr_buffer(0,1))
        subtree:add(f.activity, twr_buffer(1,1))
        subtree:add_le(f.activity_param, twr_buffer(2,2))
        pinfo.cols.info = string.format("Response Message")
        return true
    end

    -- Final Message (0x29)
    if msg_type == 0x29 and twr_buffer:len() >= 12 then
        subtree:add_le(f.final_p_ts, twr_buffer(1,5))
        subtree:add_le(f.final_r_ts, twr_buffer(6,5))
        subtree:add_le(f.final_f_ts, twr_buffer(11,5))
        pinfo.cols.info = string.format("Final Message")
        return true
    end

    -- Report Message (0x2A)
    if msg_type == 0x2A then
        subtree:add_le(f.report_p_ts, twr_buffer(6,5))
        subtree:add_le(f.report_r_ts, twr_buffer(11,5))
        subtree:add_le(f.report_f_ts, twr_buffer(16,5))
        pinfo.cols.info = "Report Message"

        -- TOF as 40-Bit-Wert (5 bytes) and take account of tics
        local tof_ps = bytes_to_40bit(twr_buffer, 1)*15.65/4
        -- TOF in nanoseconds (1 ps = 1e-3 ns)
        local tof_ns = tof_ps / 1000
        -- TOF in meter (speed of light: 0.299792458 m/ns)
        local tof_m = tof_ns * 0.299792458
        -- round value to 3 digits (mm)
        tof_m = math.floor(tof_m * 10000 + 0.5) / 10000
        subtree:add(f.tof_m, tof_m)
        return true
    end

    -- unknown type
    pinfo.cols.info = string.format("DW TWR Unknown (Type: 0x%02X)", msg_type)
end

-- try to register dissector
-- 1. UDP-Port
local udp_dissector_table = DissectorTable.get("udp.port")
if udp_dissector_table then
    udp_dissector_table:add(17754, dw_twr_proto)
    print("DW TWR Dissector registered for UDP-Port 17754.")
else
    print("ERROR: 'udp.port' DissectorTable not found!")
end

