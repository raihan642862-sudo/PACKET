package com.netcapture.pro.parser

import java.net.InetAddress
import java.time.Instant

/**
 * Small, defensive reader for classic libpcap files (not pcapng).
 * It intentionally extracts packet/protocol metadata only; it does not decrypt TLS.
 */
object PcapParser {
    const val MAX_FILE_BYTES = 32 * 1024 * 1024
    private const val MAX_PACKETS = 50_000
    private const val MAX_PACKET_BYTES = 1_048_576

    enum class Category { HTTPS, TCP, PACKET, UDP, KEY }

    data class PacketInfo(
        val timestamp: String,
        val category: Category,
        val source: String,
        val destination: String,
        val protocol: String,
        val length: Int,
        val summary: String,
        val details: List<Pair<String, String>> = emptyList()
    )

    data class Result(
        val packets: List<PacketInfo>,
        val totalFrames: Int,
        val decodedFrames: Int,
        val linkType: Long,
        val notes: List<String>
    ) {
        fun forCategory(category: Category): List<PacketInfo> = when (category) {
            Category.PACKET -> packets
            Category.KEY -> packets.filter { packet ->
                packet.details.any { it.first == "Cipher suite" || it.first == "TLS version" || it.first == "TLS server name" }
            }
            Category.TCP -> packets.filter { it.category == Category.TCP || it.category == Category.HTTPS }
            else -> packets.filter { it.category == category }
        }
    }

    fun parse(bytes: ByteArray): Result {
        require(bytes.size >= 24) { "File is too small to be a classic PCAP file." }
        require(bytes.size <= MAX_FILE_BYTES) { "File is larger than the 32 MB import limit." }

        val signature = bytes.take(4).joinToString("") { "%02X".format(it.toInt() and 0xff) }
        val littleEndian: Boolean
        val nanos: Boolean
        when (signature) {
            "D4C3B2A1" -> { littleEndian = true; nanos = false }
            "A1B2C3D4" -> { littleEndian = false; nanos = false }
            "4D3CB2A1" -> { littleEndian = true; nanos = true }
            "A1B23C4D" -> { littleEndian = false; nanos = true }
            else -> throw IllegalArgumentException("Unsupported file signature. Choose a classic .pcap file (pcapng is not supported yet).")
        }

        val linkType = u32(bytes, 20, littleEndian)
        val notes = mutableListOf<String>()
        if (linkType !in setOf(1L, 101L, 113L)) {
            throw IllegalArgumentException("Unsupported PCAP link type $linkType. Ethernet, raw IP, and Linux cooked v1 are supported.")
        }

        val packets = mutableListOf<PacketInfo>()
        var offset = 24
        var total = 0
        var decoded = 0
        var truncated = false

        while (offset + 16 <= bytes.size && total < MAX_PACKETS) {
            val seconds = u32(bytes, offset, littleEndian)
            val fraction = u32(bytes, offset + 4, littleEndian)
            val included = u32(bytes, offset + 8, littleEndian).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
            val original = u32(bytes, offset + 12, littleEndian).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
            offset += 16
            total++

            if (included < 0 || included > MAX_PACKET_BYTES || offset + included > bytes.size) {
                truncated = true
                break
            }

            val frame = bytes.copyOfRange(offset, offset + included)
            offset += included
            val timestamp = runCatching {
                val nanoPart = if (nanos) fraction else fraction * 1_000L
                Instant.ofEpochSecond(seconds, nanoPart).toString()
            }.getOrDefault("Unknown time")
            parseFrame(frame, linkType, timestamp, original.coerceAtLeast(included))?.let {
                packets += it
                decoded++
            }
        }

        if (truncated) notes += "The file ended inside a packet record or contained an oversized frame. Remaining data was skipped."
        if (total >= MAX_PACKETS) notes += "Packet limit reached: only the first $MAX_PACKETS frames were inspected."
        if (packets.isEmpty()) notes += "No supported IPv4/IPv6 packets were found in this file."
        if (offset < bytes.size && total < MAX_PACKETS) notes += "Some trailing bytes were not interpreted."
        return Result(packets, total, decoded, linkType, notes)
    }

    private fun parseFrame(frame: ByteArray, linkType: Long, timestamp: String, originalLength: Int): PacketInfo? {
        var offset = 0
        var etherType = -1
        if (linkType == 1L) {
            if (frame.size < 14) return null
            etherType = u16(frame, 12, false)
            offset = 14
            while (etherType == 0x8100 || etherType == 0x88A8 || etherType == 0x9100) {
                if (offset + 4 > frame.size) return null
                etherType = u16(frame, offset + 2, false)
                offset += 4
            }
        } else if (linkType == 113L) {
            if (frame.size < 16) return null
            etherType = u16(frame, 14, false)
            offset = 16
        } else {
            if (frame.isEmpty()) return null
            etherType = if ((frame[0].toInt() ushr 4) and 0x0f == 6) 0x86dd else 0x0800
        }

        val version = when (etherType) {
            0x0800 -> 4
            0x86DD -> 6
            else -> return null
        }
        if (offset >= frame.size) return null

        val sourceIp: String
        val destinationIp: String
        val transport: Int
        var transportOffset: Int
        if (version == 4) {
            if (offset + 20 > frame.size) return null
            val ihl = (frame[offset].toInt() and 0x0f) * 4
            if (ihl < 20 || offset + ihl > frame.size) return null
            val totalLength = u16(frame, offset + 2, false)
            transport = frame[offset + 9].toInt() and 0xff
            sourceIp = ipv4(frame, offset + 12)
            destinationIp = ipv4(frame, offset + 16)
            transportOffset = offset + ihl
            if (totalLength < ihl) return null
        } else {
            if (offset + 40 > frame.size) return null
            transport = frame[offset + 6].toInt() and 0xff
            sourceIp = ipv6(frame, offset + 8)
            destinationIp = ipv6(frame, offset + 24)
            transportOffset = offset + 40
        }

        val baseDetails = mutableListOf(
            "IP version" to "IPv$version",
            "Source IP" to sourceIp,
            "Destination IP" to destinationIp,
            "Frame length" to "$originalLength bytes"
        )

        if (transport == 6) {
            if (transportOffset + 20 > frame.size) return null
            val sourcePort = u16(frame, transportOffset, false)
            val destinationPort = u16(frame, transportOffset + 2, false)
            val headerLength = ((frame[transportOffset + 12].toInt() ushr 4) and 0x0f) * 4
            if (headerLength < 20 || transportOffset + headerLength > frame.size) return null
            val flagsByte = frame[transportOffset + 13].toInt() and 0xff
            val flags = buildList {
                if (flagsByte and 0x02 != 0) add("SYN")
                if (flagsByte and 0x10 != 0) add("ACK")
                if (flagsByte and 0x01 != 0) add("FIN")
                if (flagsByte and 0x04 != 0) add("RST")
                if (flagsByte and 0x08 != 0) add("PSH")
                if (flagsByte and 0x20 != 0) add("URG")
            }.ifEmpty { listOf("None") }.joinToString(", ")
            val payloadStart = transportOffset + headerLength
            val payload = if (payloadStart < frame.size) frame.copyOfRange(payloadStart, frame.size) else byteArrayOf()
            val endpointSource = "$sourceIp:$sourcePort"
            val endpointDestination = "$destinationIp:$destinationPort"
            val details = baseDetails + listOf(
                "Source port" to sourcePort.toString(),
                "Destination port" to destinationPort.toString(),
                "TCP flags" to flags,
                "TCP payload" to "${payload.size} bytes"
            )
            val tls = parseTls(payload)
            val isTls = tls != null || sourcePort == 443 || destinationPort == 443
            val tlsDetails = tls?.let { listOfNotNull(
                it.sni?.let { value -> "TLS server name" to value },
                it.version?.let { value -> "TLS version" to value },
                it.cipher?.let { value -> "Cipher suite" to value },
                it.alpn?.let { value -> "ALPN" to value },
                "Decryption" to "Encrypted payload is not decrypted by this analyzer"
            ) }.orEmpty()
            return PacketInfo(
                timestamp = timestamp,
                category = if (isTls) Category.HTTPS else Category.TCP,
                source = endpointSource,
                destination = endpointDestination,
                protocol = if (isTls) "TLS over TCP" else "TCP",
                length = originalLength,
                summary = when {
                    tls?.sni != null -> "TLS handshake for ${tls.sni}"
                    tls != null -> "TLS handshake metadata detected"
                    isTls -> "TLS/HTTPS flow (encrypted payload)"
                    else -> "TCP ${flags.lowercase()}"
                },
                details = details + tlsDetails + if (tls != null) listOf("KEY tab" to "Public handshake metadata only; no secret keys") else emptyList()
            )
        }

        if (transport == 17) {
            if (transportOffset + 8 > frame.size) return null
            val sourcePort = u16(frame, transportOffset, false)
            val destinationPort = u16(frame, transportOffset + 2, false)
            val udpLength = u16(frame, transportOffset + 4, false)
            val payloadStart = transportOffset + 8
            val payloadEnd = (transportOffset + udpLength).coerceAtMost(frame.size).coerceAtLeast(payloadStart)
            val payload = if (payloadStart < payloadEnd) frame.copyOfRange(payloadStart, payloadEnd) else byteArrayOf()
            val dns = if (sourcePort == 53 || destinationPort == 53 || sourcePort == 5353 || destinationPort == 5353) parseDns(payload) else null
            val details = baseDetails + listOf(
                "Source port" to sourcePort.toString(),
                "Destination port" to destinationPort.toString(),
                "UDP length" to "$udpLength bytes"
            ) + (dns?.let { listOf("DNS name" to it) } ?: emptyList())
            return PacketInfo(
                timestamp,
                Category.UDP,
                "$sourceIp:$sourcePort",
                "$destinationIp:$destinationPort",
                if (dns != null) "UDP / DNS" else "UDP",
                originalLength,
                dns?.let { "DNS question: $it" } ?: "UDP datagram",
                details
            )
        }

        return PacketInfo(timestamp, Category.PACKET, sourceIp, destinationIp, "IP protocol $transport", originalLength, "IPv$version packet", baseDetails)
    }

    private data class TlsMetadata(val sni: String?, val version: String?, val cipher: String?, val alpn: String?)

    private fun parseTls(payload: ByteArray): TlsMetadata? {
        if (payload.size < 9 || (payload[0].toInt() and 0xff) != 22) return null
        val recordVersion = u16(payload, 1, false)
        val recordLength = u16(payload, 3, false)
        if (recordLength <= 0 || recordLength + 5 > payload.size) return null // no TCP stream reassembly in this version
        val handshakeType = payload[5].toInt() and 0xff
        val handshakeLength = u24(payload, 6, false)
        if (handshakeLength <= 0 || 9 + handshakeLength > 5 + recordLength) return null
        val bodyStart = 9
        return when (handshakeType) {
            1 -> parseClientHello(payload, bodyStart, handshakeLength, recordVersion)
            2 -> parseServerHello(payload, bodyStart, handshakeLength, recordVersion)
            else -> TlsMetadata(null, tlsVersion(recordVersion), null, null)
        }
    }

    private fun parseClientHello(data: ByteArray, start: Int, length: Int, recordVersion: Int): TlsMetadata? {
        val end = start + length
        var p = start
        if (p + 34 > end) return null
        val legacyVersion = u16(data, p, false); p += 34 // version + random
        val sessionLength = data[p++].toInt() and 0xff
        p += sessionLength
        if (p + 2 > end) return null
        val cipherLength = u16(data, p, false); p += 2
        if (cipherLength < 2 || p + cipherLength > end) return null
        val firstCipher = u16(data, p, false)
        p += cipherLength
        if (p >= end) return TlsMetadata(null, tlsVersion(legacyVersion), cipherName(firstCipher), null)
        val compressionLength = data[p++].toInt() and 0xff
        p += compressionLength
        if (p + 2 > end) return TlsMetadata(null, tlsVersion(legacyVersion), cipherName(firstCipher), null)
        val extensionsLength = u16(data, p, false); p += 2
        val extensionsEnd = (p + extensionsLength).coerceAtMost(end)
        var sni: String? = null
        var version = tlsVersion(legacyVersion)
        var alpn: String? = null
        while (p + 4 <= extensionsEnd) {
            val type = u16(data, p, false)
            val extLength = u16(data, p + 2, false)
            p += 4
            if (p + extLength > extensionsEnd) break
            when (type) {
                0 -> sni = parseSni(data, p, extLength)
                16 -> alpn = parseAlpn(data, p, extLength)
                43 -> if (extLength >= 3) {
                    val listLength = data[p].toInt() and 0xff
                    if (listLength >= 2 && p + 3 <= p + extLength) version = tlsVersion(u16(data, p + 1, false))
                }
            }
            p += extLength
        }
        return TlsMetadata(sni, version.ifBlank { tlsVersion(recordVersion) }, cipherName(firstCipher), alpn)
    }

    private fun parseServerHello(data: ByteArray, start: Int, length: Int, recordVersion: Int): TlsMetadata? {
        val end = start + length
        var p = start
        if (p + 38 > end) return null
        val legacyVersion = u16(data, p, false); p += 34
        val sessionLength = data[p++].toInt() and 0xff
        p += sessionLength
        if (p + 3 > end) return null
        val cipher = u16(data, p, false); p += 3 // cipher suite + compression method
        var version = tlsVersion(legacyVersion)
        if (p + 2 <= end) {
            val extLength = u16(data, p, false); p += 2
            val extEnd = (p + extLength).coerceAtMost(end)
            while (p + 4 <= extEnd) {
                val type = u16(data, p, false)
                val len = u16(data, p + 2, false)
                p += 4
                if (p + len > extEnd) break
                if (type == 43 && len >= 2) version = tlsVersion(u16(data, p, false))
                p += len
            }
        }
        return TlsMetadata(null, version.ifBlank { tlsVersion(recordVersion) }, cipherName(cipher), null)
    }

    private fun parseSni(data: ByteArray, start: Int, length: Int): String? {
        var p = start + 2 // server-name-list length
        val end = (start + length).coerceAtMost(data.size)
        while (p + 3 <= end) {
            val nameType = data[p].toInt() and 0xff
            val nameLength = u16(data, p + 1, false)
            p += 3
            if (p + nameLength > end) return null
            if (nameType == 0) return data.copyOfRange(p, p + nameLength).toString(Charsets.US_ASCII).takeIf { it.isNotBlank() }
            p += nameLength
        }
        return null
    }

    private fun parseAlpn(data: ByteArray, start: Int, length: Int): String? {
        var p = start + 2
        val end = (start + length).coerceAtMost(data.size)
        val values = mutableListOf<String>()
        while (p < end) {
            val n = data[p++].toInt() and 0xff
            if (n == 0 || p + n > end) break
            values += data.copyOfRange(p, p + n).toString(Charsets.US_ASCII)
            p += n
        }
        return values.takeIf { it.isNotEmpty() }?.joinToString(", ")
    }

    private fun parseDns(data: ByteArray): String? {
        if (data.size < 17) return null
        val questions = u16(data, 4, false)
        if (questions == 0) return null
        var p = 12
        val labels = mutableListOf<String>()
        var jumps = 0
        while (p < data.size && jumps < 32) {
            val n = data[p].toInt() and 0xff
            if (n == 0) break
            if (n and 0xC0 == 0xC0) return labels.joinToString(".").ifBlank { "Compressed DNS name" }
            if (n > 63 || p + 1 + n > data.size) return null
            labels += data.copyOfRange(p + 1, p + 1 + n).toString(Charsets.US_ASCII)
            p += n + 1
            jumps++
        }
        return labels.joinToString(".").takeIf { it.isNotBlank() }
    }

    private fun tlsVersion(value: Int): String = when (value) {
        0x0300 -> "SSL 3.0 (legacy)"
        0x0301 -> "TLS 1.0"
        0x0302 -> "TLS 1.1"
        0x0303 -> "TLS 1.2"
        0x0304 -> "TLS 1.3"
        else -> "Unknown (0x%04X)".format(value)
    }

    private fun cipherName(value: Int): String = when (value) {
        0x1301 -> "TLS_AES_128_GCM_SHA256 (0x1301)"
        0x1302 -> "TLS_AES_256_GCM_SHA384 (0x1302)"
        0x1303 -> "TLS_CHACHA20_POLY1305_SHA256 (0x1303)"
        0xC02F -> "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)"
        0xC030 -> "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xC030)"
        0xC02B -> "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xC02B)"
        0xC02C -> "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xC02C)"
        else -> "Unknown cipher suite (0x%04X)".format(value)
    }

    private fun ipv4(data: ByteArray, p: Int): String = (0..3).joinToString(".") { (data[p + it].toInt() and 0xff).toString() }

    private fun ipv6(data: ByteArray, p: Int): String = runCatching {
        InetAddress.getByAddress(data.copyOfRange(p, p + 16)).hostAddress ?: "IPv6"
    }.getOrDefault("IPv6")

    private fun u8(data: ByteArray, p: Int): Int = data[p].toInt() and 0xff
    private fun u16(data: ByteArray, p: Int, little: Boolean): Int = if (little) {
        u8(data, p) or (u8(data, p + 1) shl 8)
    } else {
        (u8(data, p) shl 8) or u8(data, p + 1)
    }

    private fun u24(data: ByteArray, p: Int, little: Boolean): Int = if (little) {
        u8(data, p) or (u8(data, p + 1) shl 8) or (u8(data, p + 2) shl 16)
    } else {
        (u8(data, p) shl 16) or (u8(data, p + 1) shl 8) or u8(data, p + 2)
    }

    private fun u32(data: ByteArray, p: Int, little: Boolean): Long = if (little) {
        (u8(data, p).toLong()) or (u8(data, p + 1).toLong() shl 8) or
            (u8(data, p + 2).toLong() shl 16) or (u8(data, p + 3).toLong() shl 24)
    } else {
        (u8(data, p).toLong() shl 24) or (u8(data, p + 1).toLong() shl 16) or
            (u8(data, p + 2).toLong() shl 8) or u8(data, p + 3).toLong()
    }
}
