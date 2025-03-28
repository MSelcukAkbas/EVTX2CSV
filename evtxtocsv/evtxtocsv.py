"""
EVTX to CSV Dönüştürücü Kütüphanesi

Bu kütüphane Windows Olay Günlüğü (EVTX) dosyalarını CSV formatına dönüştürmek için
kullanılır. Windows sistemlerinde yönetici izniyle çalıştırılması gerekebilir.

Örnek Kullanım:
--------------
    from evtxtocsv import EvtxToCsv
    
    # Tüm logları dönüştürme
    converter = EvtxToCsv()
    converter.convert_all_logs()
    
    # Belirli kategorideki logları dönüştürme
    converter = EvtxToCsv()
    logs = converter.get_logs_by_category("Security")
    converter.convert_logs(logs)
"""

import os
import subprocess
import sys
import ctypes
from functools import wraps
from typing import List, Set, Dict, Union, Optional, Any

__version__ = "1.0.0"
__author__ = "Author"

def run_as_admin(func):
    """
    Fonksiyonu yönetici haklarıyla çalıştırmayı deneyen dekoratör.
    PermissionError alındığında kullanıcıya yönetici olarak çalıştırma seçeneği sunar.
    
    Args:
        func: Çalıştırılacak fonksiyon
        
    Returns:
        Fonksiyonun sonucu veya boş liste (yönetici hakları reddedilirse)
    
    Raises:
        PermissionError: Yönetici hakları reddedilirse
        Exception: Windows dışında bir platformda çalıştırılırsa
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        try: return func(*args, **kwargs)
        except PermissionError:
            if sys.platform != "win32": raise Exception("Yalnızca Windows desteği.")
            print("\nYönetici yetkisi gerekli olabilir. Yönetici olarak yeniden başlatılsın mı?")
            response = input("Evet/Yes (Y) veya Hayır/No (N): ").lower()
            if response in ['y', 'yes', 'e', 'evet']:
                os.system(f'runas /user:Administrator "{sys.executable}" {" ".join(sys.argv)}')
                return []
            else:
                raise PermissionError("Yönetici yetkisiyle işlem yapılmadı.")
    return wrapper

class EvtxToCsv:
    """
    Windows Olay Günlüğü (EVTX) dosyalarını CSV formatına dönüştüren sınıf.
    
    Bu sınıf, Windows sistemlerindeki EVTX günlük dosyalarını bulma, kategorilere ayırma
    ve PowerShell kullanarak CSV formatına dönüştürme yeteneklerine sahiptir.
    
    Attributes:
        LOG_DIR_PATH (str): EVTX dosyalarının bulunduğu klasör yolu
        DEFAULT_FOLDER_NAME (str): Çıktıların kaydedileceği varsayılan klasör adı
        OUTPUT_PS1 (str): Oluşturulacak PowerShell betiğinin adı
        EVTX_LOGS_BY_CATEGORY (dict): Kategori bazında EVTX dosya listesi
        CRITICAL_CATEGORIES (list): Kritik önem taşıyan kategori listesi
        DEFAULT_LOG_FILES (list): Varsayılan olarak işlenecek log dosyaları
    """
    
    # Kategori bazında EVTX dosya listesi
    EVTX_LOGS_BY_CATEGORY ={
        "System": [
            r"System.evtx",
            r"Security.evtx",
            r"Application.evtx",
            r"Setup.evtx",
            r"State.evtx",
            r"Parameters.evtx",
            r"Microsoft-Windows-Kernel-Boot%4Operational.evtx",
            r"Microsoft-Windows-Kernel-Power%4Thermal-Operational.evtx",
            r"Microsoft-Windows-Kernel-StoreMgr%4Operational.evtx",
            r"Microsoft-Windows-Kernel-WDI%4Operational.evtx",
            r"Microsoft-Windows-Kernel-WHEA%4Errors.evtx",
            r"Microsoft-Windows-Kernel-WHEA%4Operational.evtx",
            r"Microsoft-Windows-Kernel-EventTracing%4Admin.evtx",
            r"Microsoft-Windows-Kernel-IO%4Operational.evtx",
            r"Microsoft-Windows-Kernel-LiveDump%4Operational.evtx",
            r"Microsoft-Windows-Kernel-PRM%4Operational.evtx",
            r"Microsoft-Windows-Kernel-ShimEngine%4Operational.evtx",
            r"Microsoft-Windows-Kernel-CPU-Starvation%4Operational.evtx",
            r"Microsoft-Windows-Kernel-Cache%4Operational.evtx",
            r"Microsoft-Windows-Kernel-Dump%4Operational.evtx"
        ],
        "Hardware": [
            r"Microsoft-Windows-Kernel-PnP%4Configuration.evtx",
            r"Microsoft-Windows-Kernel-PnP%4Device Management.evtx",
            r"Microsoft-Windows-Kernel-PnP%4Driver Watchdog.evtx",
            r"Microsoft-Windows-Storage-ClassPnP%4Operational.evtx",
            r"Microsoft-Windows-Storage-NvmeDisk%4Operational.evtx",
            r"Microsoft-Windows-USB-UCMUCSICX%4Operational.evtx",
            r"Microsoft-Windows-USB-USBXHCI-Operational.evtx",
            r"Microsoft-Windows-PCI%4Operational.evtx",
            r"Microsoft-Windows-Hyper-V-Compute-Admin.evtx",
            r"Microsoft-Windows-Hyper-V-Compute-Operational.evtx",
            r"Microsoft-Windows-Hyper-V-Config-Admin.evtx",
            r"Microsoft-Windows-Hyper-V-Config-Operational.evtx",
            r"Microsoft-Windows-Hyper-V-Guest-Drivers%4Admin.evtx",
            r"Microsoft-Windows-Hyper-V-Hierarchical-NIC-Switch%4Operational.evtx",
            r"Microsoft-Windows-Hyper-V-Hypervisor-Admin.evtx",
            r"Microsoft-Windows-Hyper-V-Hypervisor-Operational.evtx",
            r"Microsoft-Windows-Hyper-V-StorageVSP-Admin.evtx",
            r"Microsoft-Windows-Hyper-V-VID-Admin.evtx",
            r"Microsoft-Windows-Hyper-V-VMMS-Admin.evtx",
            r"Microsoft-Windows-Hyper-V-VMMS-Networking.evtx"
        ],
        "Network": [
            r"Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx",
            r"Microsoft-Windows-Wired-AutoConfig%4Operational.evtx",
            r"Microsoft-Windows-WinHttp%4Operational.evtx",
            r"Microsoft-Windows-WinINet%4Operational.evtx",
            r"Microsoft-Windows-NCSI%4Operational.evtx",
            r"Microsoft-Windows-Dhcp-Client%4Admin.evtx",
            r"Microsoft-Windows-Dhcpv6-Client%4Admin.evtx",
            r"Microsoft-Windows-NetworkProfile%4Operational.evtx",
            r"Microsoft-Windows-NetworkProvider%4Operational.evtx",
            r"Microsoft-Windows-NetworkProvisioning%4Operational.evtx",
            r"Microsoft-Windows-SMBServer%4Audit.evtx",
            r"Microsoft-Windows-SMBServer%4Connectivity.evtx",
            r"Microsoft-Windows-SMBServer%4Operational.evtx",
            r"Microsoft-Windows-SMBServer%4Security.evtx",
            r"Microsoft-Windows-SMBWitnessClient%4Admin.evtx",
            r"Microsoft-Windows-SMBWitnessClient%4Informational.evtx",
            r"Microsoft-Windows-SMBClient%4Audit.evtx",
            r"Microsoft-Windows-SMBClient%4Connectivity.evtx",
            r"Microsoft-Windows-SMBClient%4Security.evtx",
            r"Microsoft-Windows-SMBDirect%4Connectivity.evtx"
        ],
        "Security": [
            r"Microsoft-Windows-Security-Audit-Configuration-Client%4Operational.evtx",
            r"Microsoft-Windows-Security-EnterpriseData-FileRevocationManager%4Operational.evtx",
            r"Microsoft-Windows-Security-Mitigations%4KernelMode.evtx",
            r"Microsoft-Windows-Security-Mitigations%4UserMode.evtx",
            r"Microsoft-Windows-Security-Netlogon%4Operational.evtx",
            r"Microsoft-Windows-Windows Defender%4Operational.evtx",
            r"Microsoft-Windows-Windows Firewall With Advanced Security%4Firewall.evtx",
            r"Microsoft-Windows-BitLocker%4BitLocker Management.evtx",
            r"Microsoft-Windows-DeviceGuard%4Operational.evtx",
            r"Microsoft-Windows-CodeIntegrity%4Operational.evtx",
            r"Microsoft-Windows-Security-UserConsentVerifier%4Audit.evtx",
            r"Microsoft-Windows-Security-SPP-UX-GenuineCenter-Logging%4Operational.evtx",
            r"Microsoft-Windows-Security-SPP-UX-Notifications%4ActionCenter.evtx",
            r"Microsoft-Windows-Security-Isolation-BrokeringFileSystem%4Operational.evtx",
            r"Microsoft-Windows-Security-LessPrivilegedAppContainer%4Operational.evtx",
            r"Microsoft-Windows-SecurityMitigationsBroker%4Operational.evtx",
            r"Microsoft-Windows-Security-Audit-Logging%4Operational.evtx",
            r"Microsoft-Windows-Security-Auditing%4Operational.evtx",
            r"Microsoft-Windows-Security-Auditing-Credential_Validation%4Operational.evtx",
            r"Microsoft-Windows-Security-Auditing-Policy%4Operational.evtx"
        ],
        "Storage": [
            r"Microsoft-Windows-StorageSpaces-Api%4Operational.evtx",
            r"Microsoft-Windows-StorageSpaces-Driver%4Operational.evtx",
            r"Microsoft-Windows-StorageSpaces-ManagementAgent%4WHC.evtx",
            r"Microsoft-Windows-StorageSpaces-Parser%4Operational.evtx",
            r"Microsoft-Windows-StorageSpaces-SpaceManager%4Operational.evtx",
            r"Microsoft-Windows-StorageManagement%4Operational.evtx",
            r"Microsoft-Windows-StorageManagement-PartUtil%4Operational.evtx",
            r"Microsoft-Windows-StorageSettings%4Diagnostic.evtx",
            r"Microsoft-Windows-StorageVolume%4Diagnostic.evtx",
            r"Microsoft-Windows-StorageVolume%4Operational.evtx",
            r"Microsoft-Windows-Storage-Storport%4Health.evtx",
            r"Microsoft-Windows-Storage-Storport%4Operational.evtx",
            r"Microsoft-Windows-Storage-Tiering%4Admin.evtx",
            r"Microsoft-Windows-StorageSpaces-Driver%4Diagnostic.evtx",
            r"Microsoft-Windows-StorageSpaces-Parser%4Diagnostic.evtx",
            r"Microsoft-Windows-StorageSpaces-SpaceManager%4Diagnostic.evtx",
            r"Microsoft-Windows-StorageSpaces-ManagementAgent%4WHC.evtx",
            r"Microsoft-Windows-StorageSpaces-Api%4Operational.evtx",
            r"Microsoft-Windows-StorageSpaces-Driver%4Operational.evtx",
            r"Microsoft-Windows-StorageSpaces-ManagementAgent%4WHC.evtx"
        ],
        "Application": [
            r"Microsoft-Windows-Application-Experience%4Program-Compatibility-Assistant.evtx",
            r"Microsoft-Windows-Application-Experience%4Program-Compatibility-Troubleshooter.evtx",
            r"Microsoft-Windows-Application-Experience%4Program-Inventory.evtx",
            r"Microsoft-Windows-Application-Experience%4Program-Telemetry.evtx",
            r"Microsoft-Windows-Application-Experience%4Steps-Recorder.evtx",
            r"Microsoft-Windows-AppHost%4Admin.evtx",
            r"Microsoft-Windows-AppID%4Operational.evtx",
            r"Microsoft-Windows-AppModel-Runtime%4Admin.evtx",
            r"Microsoft-Windows-AppReadiness%4Admin.evtx",
            r"Microsoft-Windows-AppReadiness%4Operational.evtx",
            r"Microsoft-Windows-AppXDeployment%4Operational.evtx",
            r"Microsoft-Windows-AppXDeployment-Server%4Operational.evtx",
            r"Microsoft-Windows-AppXDeploymentServer%4Operational.evtx",
            r"Microsoft-Windows-AppXDeploymentServer%4Restricted.evtx",
            r"Microsoft-Windows-ApplicabilityEngine%4Operational.evtx",
            r"Microsoft-Windows-Application Server-Applications%4Admin.evtx",
            r"Microsoft-Windows-Application Server-Applications%4Operational.evtx",
            r"Microsoft-Windows-AppxPackaging%4Operational.evtx",
            r"Microsoft-Windows-AssignedAccess%4Admin.evtx",
            r"Microsoft-Windows-AssignedAccessBroker%4Admin.evtx"
        ],
        "Service": [
            r"Microsoft-Windows-PowerShell%4Admin.evtx",
            r"Microsoft-Windows-PowerShell%4Operational.evtx",
            r"Microsoft-Windows-WindowsUpdateClient%4Operational.evtx",
            r"Microsoft-Windows-Winlogon%4Operational.evtx",
            r"Microsoft-Windows-TaskScheduler%4Maintenance.evtx",
            r"Microsoft-Windows-Time-Service%4Operational.evtx",
            r"Microsoft-Windows-User Profile Service%4Operational.evtx",
            r"Microsoft-Windows-Backup.evtx",
            r"Microsoft-Windows-Bits-Client%4Operational.evtx",
            r"Microsoft-Windows-WorkFolders%4Operational.evtx",
            r"Microsoft-Windows-TerminalServices-LocalSessionManager%4Admin.evtx",
            r"Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
            r"Microsoft-Windows-TerminalServices-PnPDevices%4Admin.evtx",
            r"Microsoft-Windows-TerminalServices-PnPDevices%4Operational.evtx",
            r"Microsoft-Windows-TerminalServices-Printers%4Admin.evtx",
            r"Microsoft-Windows-TerminalServices-Printers%4Operational.evtx",
            r"Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx",
            r"Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Admin.evtx",
            r"Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
            r"Microsoft-Windows-TerminalServices-ServerUSBDevices%4Admin.evtx"
        ],
        "Diagnostic": [
            r"Microsoft-Windows-Diagnosis-DPS%4Operational.evtx",
            r"Microsoft-Windows-Diagnosis-PCW%4Operational.evtx",
            r"Microsoft-Windows-Diagnosis-PLA%4Operational.evtx",
            r"Microsoft-Windows-Diagnosis-Scheduled%4Operational.evtx",
            r"Microsoft-Windows-Diagnosis-Scripted%4Admin.evtx",
            r"Microsoft-Windows-Diagnosis-Scripted%4Operational.evtx",
            r"Microsoft-Windows-Diagnostics-Networking%4Operational.evtx",
            r"Microsoft-Windows-Diagnostics-Performance%4Operational.evtx",
            r"Microsoft-Windows-DiskDiagnostic%4Operational.evtx",
            r"Microsoft-Windows-DiskDiagnosticDataCollector%4Operational.evtx",
            r"Microsoft-Windows-Diagnosis-ScriptedDiagnosticsProvider%4Operational.evtx",
            r"Microsoft-Windows-Diagnosis-PLA%4Operational.evtx",
            r"Microsoft-Windows-Diagnosis-Scheduled%4Operational.evtx",
            r"Microsoft-Windows-Diagnosis-Scripted%4Admin.evtx",
            r"Microsoft-Windows-Diagnosis-Scripted%4Operational.evtx",
            r"Microsoft-Windows-Diagnostics-Networking%4Operational.evtx",
            r"Microsoft-Windows-Diagnostics-Performance%4Operational.evtx",
            r"Microsoft-Windows-DiskDiagnostic%4Operational.evtx",
            r"Microsoft-Windows-DiskDiagnosticDataCollector%4Operational.evtx",
            r"Microsoft-Windows-DiskDiagnosticResolver%4Operational.evtx"
        ],
        "User": [
            r"Microsoft-Windows-User Control Panel%4Operational.evtx",
            r"Microsoft-Windows-User Device Registration%4Admin.evtx",
            r"Microsoft-Windows-User-Loader%4Operational.evtx",
            r"Microsoft-Windows-UserPnp%4ActionCenter.evtx",
            r"Microsoft-Windows-UserPnp%4DeviceInstall.evtx",
            r"Microsoft-Windows-UserSettingsBackup-BackupUnitProcessor%4Operational.evtx",
            r"Microsoft-Windows-UserSettingsBackup-EarlyDownloader%4Operational.evtx",
            r"Microsoft-Windows-UserSettingsBackup-Orchestrator%4Operational.evtx",
            r"Microsoft-Windows-User Experience Virtualization-Agent Driver%4Operational.evtx",
            r"Microsoft-Windows-User Experience Virtualization-App Agent%4Operational.evtx",
            r"Microsoft-Windows-User Experience Virtualization-IPC%4Operational.evtx",
            r"Microsoft-Windows-User Experience Virtualization-SQM Uploader%4Operational.evtx",
            r"Microsoft-Windows-User Profile Service%4Operational.evtx",
            r"Microsoft-Windows-User-Loader%4Operational.evtx",
            r"Microsoft-Windows-UserPnp%4ActionCenter.evtx",
            r"Microsoft-Windows-UserPnp%4DeviceInstall.evtx",
            r"Microsoft-Windows-UserSettingsBackup-BackupUnitProcessor%4Operational.evtx",
            r"Microsoft-Windows-UserSettingsBackup-EarlyDownloader%4Operational.evtx",
            r"Microsoft-Windows-UserSettingsBackup-Orchestrator%4Operational.evtx",
            r"Microsoft-Windows-User Experience Virtualization-Agent Driver%4Operational.evtx"
        ],
        "Other": [
            r"Visual Studio.evtx",
            r"Windows PowerShell.evtx",
            r"OutLog.evtx",
            r"PowerBiosServerLog.evtx",
            r"SMSApi.evtx",
            r"Microsoft-Windows-Shell-Core%4Operational.evtx",
            r"Microsoft-Windows-Shell-Core%4AppDefaults.evtx",
            r"Microsoft-Windows-Shell-Core%4LogonTasksChannel.evtx",
            r"Microsoft-Windows-ShellCommon-StartLayoutPopulation%4Operational.evtx",
            r"Microsoft-Windows-StateRepository%4Operational.evtx",
            r"Microsoft-Windows-Shell-Core%4ActionCenter.evtx",
            r"Microsoft-Windows-Shell-Core%4AppDefaults.evtx",
            r"Microsoft-Windows-Shell-Core%4LogonTasksChannel.evtx",
            r"Microsoft-Windows-ShellCommon-StartLayoutPopulation%4Operational.evtx",
            r"Microsoft-Windows-StateRepository%4Operational.evtx",
            r"Microsoft-Windows-Shell-Core%4ActionCenter.evtx",
            r"Microsoft-Windows-Shell-Core%4AppDefaults.evtx",
            r"Microsoft-Windows-Shell-Core%4LogonTasksChannel.evtx",
            r"Microsoft-Windows-ShellCommon-StartLayoutPopulation%4Operational.evtx",
            r"Microsoft-Windows-StateRepository%4Operational.evtx"
        ]
    } 

    # Sabit yapılandırma değişkenleri
    LOG_DIR_PATH = r"C:\Windows\System32\winevt\Logs"
    CRITICAL_CATEGORIES = ["System", "Security", "Application"]
    DEFAULT_LOG_FILES = [
        "System.evtx",
        "Security.evtx",
        "Application.evtx",
        "Setup.evtx"
    ]
    
    # Çıkış yapılandırma değişkenleri
    DEFAULT_FOLDER_NAME = "evtx_csv_output"
    OUTPUT_PS1 = "evtx_to_csv.ps1"

    def __init__(self, output_directory: Optional[str] = None):
        """
        EvtxToCsv sınıfının yapıcı metodu.
        
        Args:
            output_directory: CSV dosyalarının kaydedileceği dizin. Belirtilmezse,
                              DEFAULT_FOLDER_NAME kullanılır.
        """
        self.output_directory = output_directory or self.DEFAULT_FOLDER_NAME
        os.makedirs(self.output_directory, exist_ok=True)

    @staticmethod
    def is_admin() -> bool:
        """
        Mevcut işlemin yönetici haklarıyla çalışıp çalışmadığını kontrol eder.
        
        Returns:
            bool: İşlem yönetici haklarıyla çalışıyorsa True, aksi halde False
        """
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False

    def get_full_path(self, filename: Union[str, List[str]]) -> Union[str, List[str]]:
        """
        Dosya adını veya adlarını tam yola dönüştürür.
        
        Args:
            filename: Tek bir dosya adı (str) veya dosya adları listesi (List[str])
            
        Returns:
            Tam dosya yolu veya yolları
        """
        if isinstance(filename, list):
            return [os.path.join(self.LOG_DIR_PATH, f) for f in filename]
        else:
            return os.path.join(self.LOG_DIR_PATH, filename)

    @staticmethod
    def check_file_exists(filepath: str) -> bool:
        """
        Belirtilen dosyanın var olup olmadığını kontrol eder.
        
        Args:
            filepath: Kontrol edilecek dosyanın yolu
            
        Returns:
            bool: Dosya varsa True, yoksa False
        """
        return os.path.exists(filepath)

    @run_as_admin
    def get_all_log_files_names(self) -> Set[str]:
        """
        Sistemdeki tüm EVTX log dosyalarının adlarını alır.
        
        Returns:
            Set[str]: Benzersiz EVTX dosya adları kümesi
            
        Note:
            Bu işlev yönetici hakları gerektirebilir.
        """
        all_files = os.listdir(self.LOG_DIR_PATH)
        all_files = [os.path.join(self.LOG_DIR_PATH, f) for f in all_files]
        all_files = [os.path.basename(f) for f in all_files]
        unique_files = set(all_files)
        return unique_files

    @run_as_admin
    def get_all_log_paths(self) -> List[str]:
        """
        Sistemdeki tüm EVTX log dosyalarının tam yollarını alır.
        
        Returns:
            List[str]: EVTX dosyalarının tam yollarının listesi
            
        Note:
            Bu işlev yönetici hakları gerektirebilir.
        """
        return [self.get_full_path(log) for log in self.get_all_log_files_names()]

    @run_as_admin
    def check_log_exists(self, log_file: str) -> Union[str, bool]:
        """
        Belirtilen log dosyasının var olup olmadığını kontrol eder.
        
        Args:
            log_file: Kontrol edilecek log dosyasının adı
            
        Returns:
            str: Dosya varsa tam yol, yoksa False
            
        Note:
            Bu işlev yönetici hakları gerektirebilir.
        """
        full_path = self.get_full_path(log_file)
        exists = self.check_file_exists(full_path)

        if exists:
            return full_path
        else:
            return False

    def get_all_categories(self) -> List[str]:
        """
        Tanımlı tüm log kategorilerini döndürür.
        
        Returns:
            List[str]: Kategori adlarının listesi
        """
        return list(self.EVTX_LOGS_BY_CATEGORY.keys())

    def get_logs_by_category(self, category_name: str = "System") -> List[str]:
        """
        Belirtilen kategorideki log dosyalarını döndürür.
        
        Args:
            category_name: İstenen kategori adı
            
        Returns:
            List[str]: Kategorideki log dosyalarının listesi, kategori yoksa hata mesajı
        """
        category_name = category_name.lower()
        
        for key in self.get_all_categories():
            if key.lower() == category_name:
                return self.EVTX_LOGS_BY_CATEGORY[key]
                
        return []

    def get_critical_logs(self) -> List[str]:
        """
        Sistemdeki kritik log dosyalarını (varsa) döndürür.
        
        Returns:
            List[str]: Kritik log dosyalarının listesi
        """
        critical_logs = []
        for category in self.CRITICAL_CATEGORIES:
            if category in self.EVTX_LOGS_BY_CATEGORY:
                for log_file in self.EVTX_LOGS_BY_CATEGORY[category]:
                    if self.check_log_exists(log_file):
                        critical_logs.append(log_file)
        return critical_logs

    @run_as_admin
    def generate_evtx_to_csv_ps1(self, evtx_files: List[str]) -> str:
        """
        Verilen EVTX dosya yollarına göre bir PowerShell betiği oluşturur.
        
        Args:
            evtx_files: EVTX dosya yollarının listesi
            
        Returns:
            str: Oluşturulan PowerShell betiğinin yolu
            
        Note:
            Bu işlev yönetici hakları gerektirebilir.
        """
        ps1_path = os.path.join(self.output_directory, self.OUTPUT_PS1)

        with open(ps1_path, "w", encoding="utf-8") as f:
            f.write(f"""# Yönetici olarak çalıştırılmasını kontrol et
$CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object Security.Principal.WindowsPrincipal($CurrentUser)
$IsAdmin = $Principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-Not $IsAdmin) {{
    Write-Host "Yönetici izinleri gerekiyor. Betik yeniden başlatılıyor..."
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}}

# Betiğin çalıştığı dizinde çıktı klasörü oluştur
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$OutputDir = "$ScriptDir\\{self.output_directory}"

if (!(Test-Path $OutputDir)) {{
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}}

""")

            # EVTX dosyalarını işleme ekle
            for evtx_path in evtx_files:
                evtx_file = os.path.basename(evtx_path)
                csv_name = evtx_file.replace(".evtx", ".csv")
                csv_path = f"$OutputDir\\{csv_name}"

                f.write(f"""
# {evtx_file} için dönüşüm
if (Test-Path "{evtx_path}") {{
    try {{
        $eventCount = Get-WinEvent -Path "{evtx_path}" -MaxEvents 1 -ErrorAction Stop
        if ($eventCount) {{
            Get-WinEvent -Path "{evtx_path}" | Export-Csv -Path {csv_path} -NoTypeInformation -Encoding UTF8
            Write-Host "Exported: {csv_path}"
        }} else {{
            Write-Host "Uyarı: {evtx_file} içinde olay bulunamadı, atlanıyor."
        }}
    }} catch {{
        Write-Host "Hata: {evtx_file} okunamadı, atlanıyor."
    }}
}} else {{
    Write-Host "Uyarı: {evtx_file} bulunamadı, atlanıyor."
}}
""")

        print(f"PowerShell betiği oluşturuldu: {ps1_path}")
        return ps1_path

    def execute_ps1_as_admin(self, ps1_path: Optional[str] = None) -> Dict[str, Any]:
        """
        PowerShell betiğini yönetici olarak çalıştırır.
        
        Args:
            ps1_path: Çalıştırılacak PowerShell betiğinin yolu. Belirtilmezse,
                      output_directory/OUTPUT_PS1 kullanılır.
                      
        Returns:
            Dict: İşlem sonucu bilgilerini içeren sözlük
                {
                    'success': bool,    # İşlem başarılı mı
                    'stdout': str,      # Standart çıktı
                    'stderr': str,      # Hata çıktısı (varsa)
                    'error': Exception  # Hata (varsa)
                }
        """
        if not ps1_path:
            ps1_path = os.path.join(os.getcwd(), self.output_directory, self.OUTPUT_PS1)

        result = {
            'success': False,
            'stdout': '',
            'stderr': '',
            'error': None
        }

        try:
            # Karakter kodlama sorununu gidermek için text=False kullanıp
            # sonra utf-8 ile decode edelim
            process = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ps1_path],
                check=True,
                shell=False,
                capture_output=True,
                text=False  # Bytes olarak çıktı al
            )
            result['success'] = True
            
            # Güvenli şekilde decode etme işlemi
            try:
                result['stdout'] = process.stdout.decode('utf-8', errors='replace')
            except UnicodeError:
                result['stdout'] = process.stdout.decode('cp1254', errors='replace')
                
            try:
                result['stderr'] = process.stderr.decode('utf-8', errors='replace')
            except UnicodeError:
                result['stderr'] = process.stderr.decode('cp1254', errors='replace')
            
            print("[✓] PowerShell betiği başarıyla çalıştırıldı.")
            if result['stdout']:
                print("PowerShell çıktısı:")
                print(result['stdout'])
                
        except subprocess.CalledProcessError as e:
            result['success'] = False
            result['error'] = e
            
            # Hata çıktılarını güvenli şekilde decode et
            try:
                result['stdout'] = e.stdout.decode('utf-8', errors='replace')
            except (UnicodeError, AttributeError):
                result['stdout'] = str(e.stdout)
                
            try:
                result['stderr'] = e.stderr.decode('utf-8', errors='replace')
            except (UnicodeError, AttributeError):
                result['stderr'] = str(e.stderr)
            
            print(f"[X] Hata: PowerShell betiği çalıştırılamadı. {e}")
            if result['stdout']:
                print("PowerShell çıktısı:")
                print(result['stdout'])
            if result['stderr']:
                print("PowerShell hata çıktısı:")
                print(result['stderr'])
                
        return result
    
    def convert_logs(self, log_files: List[str]) -> Dict[str, Any]:
        """
        Belirtilen log dosyalarını CSV formatına dönüştürür.
        
        Args:
            log_files: Dönüştürülecek log dosyalarının listesi
            
        Returns:
            Dict: İşlem sonucu
        """
        ps1_path = self.generate_evtx_to_csv_ps1(log_files)
        return self.execute_ps1_as_admin(ps1_path)
    
    def convert_all_logs(self) -> Dict[str, Any]:
        """
        Sistemdeki tüm log dosyalarını CSV formatına dönüştürür.
        
        Returns:
            Dict: İşlem sonucu
        """
        return self.convert_logs(self.get_all_log_paths())
    
    def convert_logs_by_category(self, category: str) -> Dict[str, Any]:
        """
        Belirtilen kategorideki log dosyalarını CSV formatına dönüştürür.
        
        Args:
            category: Dönüştürülecek log dosyalarının kategorisi
            
        Returns:
            Dict: İşlem sonucu
        """
        logs = self.get_logs_by_category(category)
        if not logs:
            print(f"[!] Uyarı: '{category}' kategorisinde log bulunamadı.")
            return {'success': False, 'error': f"'{category}' kategorisi bulunamadı."}
            
        log_paths = [self.get_full_path(log) for log in logs]
        return self.convert_logs(log_paths)
    
    def convert_critical_logs(self) -> Dict[str, Any]:
        """
        Kritik log dosyalarını CSV formatına dönüştürür.
        
        Returns:
            Dict: İşlem sonucu
        """
        critical_logs = self.get_critical_logs()
        return self.convert_logs(critical_logs)


    # Örnek kullanım
    def easy_usage(self):
        """
        EvtxToCsv kütüphanesinin örnek kullanımı.
        """
        print("EVTX to CSV Dönüştürücü - Örnek Kullanım")
        print("----------------------------------------")
        
        # Kütüphaneyi başlat
        converter = EvtxToCsv()
        
        # Menü göster
        print("\nSeçenekler:")
        print("1. Tüm log dosyalarını dönüştür")
        print("2. Kritik log dosyalarını dönüştür")
        print("3. Belirli bir kategorideki log dosyalarını dönüştür")
        print("4. Çıkış")
        
        choice = input("\nSeçiminiz (1-4): ")
        
        if choice == "1":
            print("\nTüm log dosyaları dönüştürülüyor...")
            converter.convert_all_logs()
        elif choice == "2":
            print("\nKritik log dosyaları dönüştürülüyor...")
            converter.convert_critical_logs()
        elif choice == "3":
            print("\nKategoriler:")
            for i, category in enumerate(converter.get_all_categories(), 1):
                print(f"{i}. {category}")
            
            cat_choice = input("\nKategori seçin (1-10): ")
            try:
                index = int(cat_choice) - 1
                if 0 <= index < len(converter.get_all_categories()):
                    category = converter.get_all_categories()[index]
                    print(f"\n'{category}' kategorisindeki log dosyaları dönüştürülüyor...")
                    converter.convert_logs_by_category(category)
                else:
                    print("Geçersiz kategori seçimi!")
            except ValueError:
                print("Geçersiz giriş!")
        elif choice == "4":
            print("\nProgramdan çıkılıyor...")
        else:
            print("\nGeçersiz seçim!")
        
        print("\nİşlem tamamlandı.")


