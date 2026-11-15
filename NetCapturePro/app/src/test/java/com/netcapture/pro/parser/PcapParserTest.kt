package com.netcapture.pro.parser

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

class PcapParserTest {
    @Test
    fun parsesClassicPcapTcpFrame() {
        val result = PcapParser.parse(tcpPcap())
        assertEquals(1, result.totalFrames)
        assertEquals(1, result.decodedFrames)
        assertEquals("TLS over TCP", result.packets.single().protocol)
        assertEquals(PcapParser.Category.HTTPS, result.packets.single().category)
        assertEquals(1, result.forCategory(PcapParser.Category.TCP).size)
        assertEquals("192.0.2.10:51515", result.packets.single().source)
        assertEquals("198.51.100.20:443", result.packets.single().destination)
    }

    @Test
    fun rejectsUnknownSignature() {
        val invalid = ByteArray(24)
        var thrown = false
        try {
            PcapParser.parse(invalid)
        } catch (_: IllegalArgumentException) {
            thrown = true
        }
        assertTrue(thrown)
    }

    private fun tcpPcap(): ByteArray {
        val frame = ByteArray(14 + 20 + 20)
        // Ethernet II, IPv4
        frame[12] = 0x08
        frame[13] = 0x00.toByte()
        val ip = 14
        frame[ip] = 0x45
        frame[ip + 2] = 0x00
        frame[ip + 3] = 40
        frame[ip + 8] = 64
        frame[ip + 9] = 6
        byteArrayOf(192.toByte(), 0, 2, 10).copyInto(frame, ip + 12)
        byteArrayOf(198.toByte(), 51, 100, 20).copyInto(frame, ip + 16)
        val tcp = 34
        frame[tcp] = 0xC9.toByte() // source port 51515
        frame[tcp + 1] = 0x3B
        frame[tcp + 2] = 0x01
        frame[tcp + 3] = 0xBB.toByte() // destination port 443
        frame[tcp + 12] = 0x50
        frame[tcp + 13] = 0x02 // SYN

        val out = ByteArrayOutputStream()
        // Little-endian classic PCAP global header.
        out.write(byteArrayOf(0xD4.toByte(), 0xC3.toByte(), 0xB2.toByte(), 0xA1.toByte()))
        writeLe16(out, 2); writeLe16(out, 4)
        writeLe32(out, 0); writeLe32(out, 0); writeLe32(out, 65535); writeLe32(out, 1)
        // One packet record.
        writeLe32(out, 1); writeLe32(out, 0); writeLe32(out, frame.size); writeLe32(out, frame.size)
        out.write(frame)
        return out.toByteArray()
    }

    private fun writeLe16(out: ByteArrayOutputStream, value: Int) {
        out.write(value and 0xff)
        out.write((value ushr 8) and 0xff)
    }

    private fun writeLe32(out: ByteArrayOutputStream, value: Int) {
        out.write(value and 0xff)
        out.write((value ushr 8) and 0xff)
        out.write((value ushr 16) and 0xff)
        out.write((value ushr 24) and 0xff)
    }
}
