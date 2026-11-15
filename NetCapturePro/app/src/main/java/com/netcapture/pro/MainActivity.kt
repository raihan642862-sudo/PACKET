package com.netcapture.pro

import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.weight
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.netcapture.pro.parser.PcapParser
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream

private val Bg = Color(0xFF09111D)
private val Panel = Color(0xFF142235)
private val PanelAlt = Color(0xFF1A2B40)
private val Cyan = Color(0xFF48D8F2)
private val Green = Color(0xFF59DDAA)
private val Amber = Color(0xFFFFC66D)
private val White = Color(0xFFF2F6FA)
private val Muted = Color(0xFF9AAEC2)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { NetCaptureApp() }
    }
}

private enum class MainTab(val label: String) { HOME("Home"), APPS("Apps"), ANALYZE("Analyze"), SETTINGS("Settings") }
private enum class ViewTab(val label: String, val category: PcapParser.Category) {
    HTTPS("HTTPS", PcapParser.Category.HTTPS),
    TCP("TCP", PcapParser.Category.TCP),
    PACKET("PACKET", PcapParser.Category.PACKET),
    UDP("UDP", PcapParser.Category.UDP),
    KEY("KEY", PcapParser.Category.KEY)
}
private data class InstalledApp(val label: String, val packageName: String)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun NetCaptureApp() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var mainTab by remember { mutableStateOf(MainTab.HOME) }
    var viewTab by remember { mutableStateOf(ViewTab.HTTPS) }
    var apps by remember { mutableStateOf<List<InstalledApp>>(emptyList()) }
    var selectedApps by remember { mutableStateOf(setOf<String>()) }
    var appSearch by remember { mutableStateOf("") }
    var pcapResult by remember { mutableStateOf<PcapParser.Result?>(null) }
    var fileLabel by remember { mutableStateOf("No file imported") }
    var loading by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    val importLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            scope.launch {
                loading = true
                error = null
                try {
                    val parsed = withContext(Dispatchers.IO) {
                        val input = context.contentResolver.openInputStream(uri)
                            ?: throw IllegalArgumentException("Could not open the selected file.")
                        val bytes = input.use { readLimited(it, PcapParser.MAX_FILE_BYTES) }
                        PcapParser.parse(bytes)
                    }
                    pcapResult = parsed
                    fileLabel = uri.lastPathSegment?.substringAfterLast('/')?.take(48) ?: "Imported PCAP"
                    mainTab = MainTab.ANALYZE
                } catch (e: Exception) {
                    error = e.message ?: "Could not analyse this file."
                } finally {
                    loading = false
                }
            }
        }
    }

    val exportLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/csv")) { uri ->
        val result = pcapResult
        if (uri != null && result != null) {
            scope.launch {
                runCatching {
                    withContext(Dispatchers.IO) {
                        context.contentResolver.openOutputStream(uri)?.use { it.write(toCsv(result).toByteArray()) }
                            ?: throw IllegalStateException("Could not create the export file.")
                    }
                }.onFailure { error = it.message ?: "Export failed." }
            }
        }
    }

    LaunchedEffect(Unit) {
        apps = withContext(Dispatchers.IO) {
            val pm = context.packageManager
            val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
            @Suppress("DEPRECATION")
            pm.queryIntentActivities(launcherIntent, PackageManager.MATCH_ALL)
                .mapNotNull { item ->
                    val info = item.activityInfo.applicationInfo
                    if (info.packageName == context.packageName) null
                    else InstalledApp(item.loadLabel(pm).toString(), info.packageName)
                }
                .distinctBy { it.packageName }
                .sortedBy { it.label.lowercase() }
        }
    }

    MaterialTheme(colorScheme = darkColorScheme(primary = Cyan, secondary = Green, background = Bg, surface = Panel, onSurface = White)) {
        Scaffold(
            containerColor = Bg,
            bottomBar = {
                NavigationBar(containerColor = Color(0xFF0E1927)) {
                    MainTab.entries.forEach { tab ->
                        NavigationBarItem(
                            selected = mainTab == tab,
                            onClick = { mainTab = tab },
                            icon = { Text(when (tab) { MainTab.HOME -> "⌂"; MainTab.APPS -> "▦"; MainTab.ANALYZE -> "⌕"; MainTab.SETTINGS -> "⚙" }, fontSize = 19.sp) },
                            label = { Text(tab.label, fontSize = 10.sp) }
                        )
                    }
                }
            }
        ) { padding ->
            Box(Modifier.fillMaxSize().padding(padding)) {
                when (mainTab) {
                    MainTab.HOME -> HomeScreen(
                        result = pcapResult,
                        fileLabel = fileLabel,
                        selectedCount = selectedApps.size,
                        loading = loading,
                        error = error,
                        onImport = { importLauncher.launch(arrayOf("application/octet-stream", "application/vnd.tcpdump.pcap", "*/*")) },
                        onAnalyze = { mainTab = MainTab.ANALYZE }
                    )
                    MainTab.APPS -> AppsScreen(
                        apps = apps,
                        search = appSearch,
                        onSearch = { appSearch = it },
                        selectedApps = selectedApps,
                        onSelectedApps = { selectedApps = it }
                    )
                    MainTab.ANALYZE -> AnalyzeScreen(
                        result = pcapResult,
                        fileLabel = fileLabel,
                        activeTab = viewTab,
                        onTabChange = { viewTab = it },
                        onImport = { importLauncher.launch(arrayOf("application/octet-stream", "application/vnd.tcpdump.pcap", "*/*")) },
                        onExport = { exportLauncher.launch("netcapture-analysis.csv") },
                        loading = loading,
                        error = error
                    )
                    MainTab.SETTINGS -> SettingsScreen()
                }
            }
        }
    }
}

private fun readLimited(input: java.io.InputStream, maxBytes: Int): ByteArray {
    val output = ByteArrayOutputStream()
    val buffer = ByteArray(8 * 1024)
    while (true) {
        val count = input.read(buffer)
        if (count < 0) break
        if (output.size() + count > maxBytes) throw IllegalArgumentException("File exceeds the ${maxBytes / (1024 * 1024)} MB import limit.")
        output.write(buffer, 0, count)
    }
    return output.toByteArray()
}

@Composable
private fun ScreenTitle(title: String, subtitle: String) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 18.dp)) {
        Text(title, color = White, fontSize = 25.sp, fontWeight = FontWeight.Bold)
        Text(subtitle, color = Muted, fontSize = 12.sp)
    }
}

@Composable
private fun HomeScreen(
    result: PcapParser.Result?, fileLabel: String, selectedCount: Int, loading: Boolean, error: String?,
    onImport: () -> Unit, onAnalyze: () -> Unit
) {
    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(bottom = 24.dp)) {
        item { ScreenTitle("NetCapture Pro", "PCAP ANALYSIS WORKSPACE") }
        item {
            Column(Modifier.padding(horizontal = 16.dp).clip(RoundedCornerShape(22.dp)).background(Panel).padding(18.dp)) {
                Text("Packet analysis", color = White, fontSize = 20.sp, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(5.dp))
                Text("Import a classic .pcap file to inspect packet headers, TCP, UDP, DNS and visible TLS handshake metadata.", color = Muted, fontSize = 12.sp)
                Spacer(Modifier.height(16.dp))
                Button(onClick = onImport, enabled = !loading, modifier = Modifier.fillMaxWidth().height(50.dp), colors = ButtonDefaults.buttonColors(containerColor = Cyan, contentColor = Bg), shape = RoundedCornerShape(14.dp)) {
                    if (loading) CircularProgressIndicator(Modifier.size(18.dp), color = Bg, strokeWidth = 2.dp)
                    else Text("IMPORT PCAP FILE", fontWeight = FontWeight.Bold)
                }
                if (error != null) Text(error, color = Amber, fontSize = 12.sp, modifier = Modifier.padding(top = 10.dp))
            }
        }
        item {
            Row(Modifier.padding(horizontal = 16.dp, vertical = 14.dp), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                MetricCard("FRAMES", result?.totalFrames?.toString() ?: "—", Modifier.weight(1f))
                MetricCard("PARSED", result?.decodedFrames?.toString() ?: "—", Modifier.weight(1f))
                MetricCard("APPS", selectedCount.toString(), Modifier.weight(1f))
            }
        }
        item {
            InfoCard("Current file", result?.let { fileLabel } ?: "No PCAP loaded", result?.let { "${it.packets.size} parsed packet records • link type ${it.linkType}" } ?: "Import an authorized diagnostic capture to begin.")
        }
        item {
            InfoCard("Important build scope", "Offline PCAP analyzer", "This GitHub build does not run a live VPN capture or decrypt third-party HTTPS. Android per-app live capture needs a traffic-forwarding VPN engine. App selection is provided as a workspace list, not as a packet-to-app attribution claim.")
        }
        if (result != null) item {
            TextButton(onClick = onAnalyze, modifier = Modifier.padding(start = 12.dp)) { Text("Open five-tab analysis →", color = Cyan) }
        }
    }
}

@Composable
private fun MetricCard(label: String, value: String, modifier: Modifier) {
    Column(modifier.clip(RoundedCornerShape(16.dp)).background(Panel).padding(13.dp)) {
        Text(label, color = Muted, fontSize = 9.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(6.dp))
        Text(value, color = Cyan, fontSize = 22.sp, fontWeight = FontWeight.Bold)
    }
}

@Composable
private fun InfoCard(title: String, heading: String, body: String) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp).clip(RoundedCornerShape(18.dp)).background(Panel).padding(16.dp)) {
        Text(title.uppercase(), color = Muted, fontSize = 9.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(6.dp))
        Text(heading, color = White, fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(5.dp))
        Text(body, color = Muted, fontSize = 11.sp, lineHeight = 16.sp)
    }
}

@Composable
private fun AppsScreen(
    apps: List<InstalledApp>, search: String, onSearch: (String) -> Unit,
    selectedApps: Set<String>, onSelectedApps: (Set<String>) -> Unit
) {
    val filtered = apps.filter { it.label.contains(search, true) || it.packageName.contains(search, true) }
    Column(Modifier.fillMaxSize()) {
        ScreenTitle("Applications", "Choose apps for your diagnostic workspace")
        OutlinedTextField(
            value = search, onValueChange = onSearch,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
            placeholder = { Text("Search installed apps") }, singleLine = true,
            shape = RoundedCornerShape(14.dp)
        )
        Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Text("${selectedApps.size} selected", color = Cyan, modifier = Modifier.weight(1f), fontWeight = FontWeight.SemiBold)
            TextButton(onClick = { onSelectedApps(filtered.map { it.packageName }.toSet()) }) { Text("Select visible") }
            TextButton(onClick = { onSelectedApps(emptySet()) }) { Text("Clear") }
        }
        Text("Note: selected apps are not automatically mapped to imported PCAP packets in this offline build.", color = Amber, fontSize = 11.sp, modifier = Modifier.padding(horizontal = 18.dp, vertical = 2.dp))
        LazyColumn(contentPadding = PaddingValues(bottom = 20.dp)) {
            items(filtered, key = { it.packageName }) { app ->
                Row(Modifier.fillMaxWidth().padding(horizontal = 18.dp, vertical = 7.dp), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text(app.label, color = White, fontWeight = FontWeight.Medium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(app.packageName, color = Muted, fontSize = 10.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                    Checkbox(selectedApps.contains(app.packageName), onCheckedChange = { checked ->
                        onSelectedApps(if (checked) selectedApps + app.packageName else selectedApps - app.packageName)
                    })
                }
            }
        }
    }
}

@Composable
private fun AnalyzeScreen(
    result: PcapParser.Result?, fileLabel: String, activeTab: ViewTab, onTabChange: (ViewTab) -> Unit,
    onImport: () -> Unit, onExport: () -> Unit, loading: Boolean, error: String?
) {
    Column(Modifier.fillMaxSize()) {
        ScreenTitle("Packet Analysis", "FIVE PROTOCOL VIEWS • OFFLINE PCAP SOURCE")
        Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(horizontal = 12.dp), horizontalArrangement = Arrangement.spacedBy(7.dp)) {
            ViewTab.entries.forEach { tab ->
                val count = result?.forCategory(tab.category)?.size ?: 0
                FilterChip(
                    selected = activeTab == tab,
                    onClick = { onTabChange(tab) },
                    label = { Text("${tab.label}  $count", fontWeight = FontWeight.SemiBold) }
                )
            }
        }
        Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 7.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(result?.let { fileLabel } ?: "No source file", color = Muted, fontSize = 11.sp, modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis)
            TextButton(onClick = onImport, enabled = !loading) { Text("Import", color = Cyan) }
            TextButton(onClick = onExport, enabled = result != null) { Text("CSV", color = Cyan) }
        }
        if (error != null) Text(error, color = Amber, fontSize = 12.sp, modifier = Modifier.padding(horizontal = 16.dp, vertical = 5.dp))
        if (result == null) {
            Box(Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.padding(24.dp)) {
                    Text("No packets to display", color = White, fontWeight = FontWeight.SemiBold)
                    Spacer(Modifier.height(6.dp))
                    Text("Import a classic .pcap file. This build does not generate sample traffic or pretend to capture live traffic.", color = Muted, fontSize = 12.sp)
                }
            }
        } else {
            val visible = result.forCategory(activeTab.category)
            if (activeTab == ViewTab.KEY) {
                InfoCard("Key inspection", "Public TLS metadata only", "The KEY view shows visible protocol version and cipher-suite metadata when present. Private encryption keys, passwords, session tokens and decrypted third-party HTTPS content are not captured.")
            }
            if (visible.isEmpty()) {
                Box(Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) { Text("No ${activeTab.label} records found in this PCAP.", color = Muted, fontSize = 12.sp) }
            } else {
                LazyColumn(Modifier.weight(1f), contentPadding = PaddingValues(bottom = 20.dp)) {
                    items(visible) { packet ->
                        PacketCard(packet)
                    }
                }
            }
            if (result.notes.isNotEmpty()) {
                Text(result.notes.joinToString("  •  "), color = Amber, fontSize = 10.sp, modifier = Modifier.padding(horizontal = 16.dp, vertical = 5.dp))
            }
        }
    }
}

@Composable
private fun PacketCard(packet: PcapParser.PacketInfo) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 14.dp, vertical = 5.dp).clip(RoundedCornerShape(15.dp)).background(Panel).padding(13.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(packet.protocol, color = Cyan, fontSize = 11.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
            Text("${packet.length} B", color = Green, fontSize = 10.sp, fontWeight = FontWeight.SemiBold)
        }
        Spacer(Modifier.height(6.dp))
        Text(packet.summary, color = White, fontSize = 13.sp, fontWeight = FontWeight.Medium)
        Spacer(Modifier.height(5.dp))
        Text("${packet.source}  →  ${packet.destination}", color = Muted, fontSize = 10.sp, maxLines = 2, overflow = TextOverflow.Ellipsis)
        Spacer(Modifier.height(4.dp))
        Text(packet.timestamp, color = Muted, fontSize = 9.sp)
        if (packet.details.isNotEmpty()) {
            Spacer(Modifier.height(9.dp))
            packet.details.take(8).forEach { (key, value) ->
                Row(Modifier.fillMaxWidth().padding(vertical = 2.dp), verticalAlignment = Alignment.Top) {
                    Text(key, color = Muted, fontSize = 10.sp, modifier = Modifier.weight(0.42f))
                    Text(value, color = White, fontSize = 10.sp, modifier = Modifier.weight(0.58f))
                }
            }
        }
    }
}

@Composable
private fun SettingsScreen() {
    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(bottom = 24.dp)) {
        item { ScreenTitle("Settings", "PRIVACY & FORMAT SUPPORT") }
        item { InfoCard("Supported source", "Classic PCAP", "This version reads classic .pcap files with Ethernet, raw IP or Linux cooked v1 link types. PCAPNG, TCP stream reassembly and full TLS decryption are not included.") }
        item { InfoCard("Data handling", "Local processing", "Imported files are parsed on the device. The app does not upload captures to a server. Export is a user-initiated CSV summary.") }
        item { InfoCard("HTTPS and KEY tabs", "Metadata, not secrets", "TLS SNI, protocol versions and recognized cipher suites may be visible when the handshake is present in a single packet. Encrypted application payloads remain encrypted.") }
        item { InfoCard("Build information", "NetCapture Pro 0.2.0", "Kotlin • Jetpack Compose • Minimum Android 12 (API 31). Use Android Studio with JDK 17 and Gradle 8.9.") }
    }
}

private fun toCsv(result: PcapParser.Result): String {
    val out = StringBuilder("timestamp,category,protocol,source,destination,length,summary,details\n")
    result.packets.forEach { packet ->
        val details = packet.details.joinToString("; ") { (k, v) -> "$k=$v" }
        val row = listOf(packet.timestamp, packet.category.name, packet.protocol, packet.source, packet.destination, packet.length.toString(), packet.summary, details)
        out.append(row.joinToString(",") { csvCell(it) }).append('\n')
    }
    return out.toString()
}

private fun csvCell(value: String): String = "\"${value.replace("\"", "\"\"")}\""
