package com.xconflictionx.xprivacyvpn

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.core.content.ContextCompat
import com.xconflictionx.xprivacyvpn.ui.MainViewModel
import com.xconflictionx.xprivacyvpn.ui.XPrivacyVpnApp
import com.xconflictionx.xprivacyvpn.vpn.VpnStateManager
import com.xconflictionx.xprivacyvpn.vpn.XPrivacyVpnService

class MainActivity : ComponentActivity() {

    private val viewModel: MainViewModel by viewModels()
    private var startTunnelAfterVpnGrant: Boolean = true

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        viewModel.refreshPermissionStatus()
        if (result.resultCode == Activity.RESULT_OK && startTunnelAfterVpnGrant) {
            startVpnService()
        }
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { _ ->
        viewModel.refreshPermissionStatus()
        if (startTunnelAfterVpnGrant) {
            prepareAndStartVpn()
        }
    }

    private val settingsActivityLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { _ ->
        viewModel.refreshPermissionStatus()
    }

    private val importFilterFilesLauncher = registerForActivityResult(
        ActivityResultContracts.OpenMultipleDocuments()
    ) { uris ->
        if (uris.isNotEmpty()) {
            viewModel.importFilterFiles(uris)
        }
    }

    private val importWgConfLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            viewModel.importWgConfUri(uri)
        }
    }

    private val exportBackupLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/json")
    ) { uri ->
        if (uri != null) {
            viewModel.exportSettingsBackup(uri)
        }
    }

    private val importBackupLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            viewModel.importSettingsBackup(uri)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        setContent {
            XPrivacyVpnApp(
                viewModel = viewModel,
                onToggleVpn = { shouldConnect ->
                    if (shouldConnect) {
                        startTunnelAfterVpnGrant = true
                        requestNotificationAndStartVpn()
                    } else {
                        stopVpnService()
                    }
                },
                onImportFilterFiles = {
                    importFilterFilesLauncher.launch(arrayOf("text/*", "application/octet-stream", "*/*"))
                },
                onImportWgConfFile = {
                    importWgConfLauncher.launch(arrayOf("*/*"))
                },
                onExportSettingsBackup = {
                    exportBackupLauncher.launch("xPrivacyVPN-backup.json")
                },
                onImportSettingsBackup = {
                    importBackupLauncher.launch(arrayOf("application/json", "text/plain", "*/*"))
                },
                onRequestDisableBatteryOptimization = {
                    openDisableBatteryOptimization()
                },
                onOpenBatteryOptimizationList = {
                    openBatteryOptimizationListSettings()
                },
                onRequestVpnPermissionOnly = {
                    startTunnelAfterVpnGrant = false
                    val prepareIntent = VpnService.prepare(this)
                    if (prepareIntent != null) {
                        vpnPermissionLauncher.launch(prepareIntent)
                    } else {
                        viewModel.refreshPermissionStatus()
                    }
                },
                onRequestNotificationPermissionOnly = {
                    startTunnelAfterVpnGrant = false
                    requestOrOpenNotificationPermission()
                },
                onOpenAppDetailsSettings = {
                    openAppDetailsSettings()
                }
            )
        }
    }

    override fun onStart() {
        super.onStart()
        VpnStateManager.setUiVisible(true)
    }

    override fun onResume() {
        super.onResume()
        viewModel.refreshPermissionStatus()
    }

    override fun onStop() {
        VpnStateManager.setUiVisible(false)
        super.onStop()
    }

    private fun requestNotificationAndStartVpn() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            prepareAndStartVpn()
        }
    }

    private fun requestOrOpenNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            runCatching {
                val intent = Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).apply {
                    putExtra(Settings.EXTRA_APP_PACKAGE, packageName)
                }
                settingsActivityLauncher.launch(intent)
            }.onFailure {
                openAppDetailsSettings()
            }
        }
    }

    @SuppressLint("BatteryLife")
    private fun openDisableBatteryOptimization() {
        runCatching {
            val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                data = Uri.parse("package:$packageName")
            }
            settingsActivityLauncher.launch(intent)
        }.onFailure {
            openBatteryOptimizationListSettings()
        }
    }

    private fun openBatteryOptimizationListSettings() {
        runCatching {
            val intent = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
            settingsActivityLauncher.launch(intent)
        }.onFailure {
            openAppDetailsSettings()
        }
    }

    private fun openAppDetailsSettings() {
        runCatching {
            val intent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                data = Uri.fromParts("package", packageName, null)
            }
            settingsActivityLauncher.launch(intent)
        }
    }

    private fun prepareAndStartVpn() {
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            startVpnService()
        }
    }

    private fun startVpnService() {
        val intent = Intent(this, XPrivacyVpnService::class.java).apply {
            action = XPrivacyVpnService.ACTION_START
        }
        ContextCompat.startForegroundService(this, intent)
    }

    private fun stopVpnService() {
        val intent = Intent(this, XPrivacyVpnService::class.java).apply {
            action = XPrivacyVpnService.ACTION_STOP
        }
        startService(intent)
    }
}
