"""Unit tests for the Phase 6D string->persistence-artifact classifier
(:func:`gomemforensics.analyzers.persistence.classify_persistence_string`).

Every test here is UNIT-level: pure Python string classification, no
memory reader, no Go runtime structures, no filesystem/registry/OS access
of any kind.
"""

from __future__ import annotations

from gomemforensics.analyzers.persistence import (
    MAX_PERSISTENCE_VALUE_LENGTH,
    classify_persistence_string,
    redact_value,
)
from gomemforensics.analyzers.models import PersistenceArtifactType
from gomemforensics.common.models import Confidence


def _type(value: str):
    result = classify_persistence_string(value)
    return result.artifact_type if result else None


def _platform(value: str):
    result = classify_persistence_string(value)
    return result.platform if result else None


class TestWindowsRegistry:
    def test_hkcu_run_key(self):
        result = classify_persistence_string(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run")
        assert result.artifact_type == PersistenceArtifactType.WINDOWS_REGISTRY_RUN
        assert result.platform == "windows"
        assert result.confidence == Confidence.HIGH
        assert result.persistence_mechanism == "registry_run_key"

    def test_hklm_runonce_key(self):
        result = classify_persistence_string(r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce")
        assert result.persistence_mechanism == "registry_runonce_key"

    def test_winlogon_shell(self):
        result = classify_persistence_string(r"Winlogon\Shell")
        assert result.artifact_type == PersistenceArtifactType.WINDOWS_WINLOGON

    def test_winlogon_userinit(self):
        assert _type(r"Winlogon\Userinit") == PersistenceArtifactType.WINDOWS_WINLOGON

    def test_startup_folder(self):
        value = r"C:\Users\test\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.lnk"
        assert _type(value) == PersistenceArtifactType.WINDOWS_STARTUP_FOLDER

    def test_appinit_dlls(self):
        assert _type("AppInit_DLLs") == PersistenceArtifactType.WINDOWS_APPINIT

    def test_ifeo(self):
        result = classify_persistence_string(r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options")
        assert result.artifact_type == PersistenceArtifactType.WINDOWS_IFEO


class TestWindowsServicesAndTasks:
    def test_schtasks_create_command(self):
        result = classify_persistence_string("schtasks /create /tn Fake /tr fake.exe")
        assert result.artifact_type == PersistenceArtifactType.WINDOWS_SCHEDULED_TASK_REFERENCE
        assert "COMMAND" in result.notes

    def test_new_scheduled_task_powershell(self):
        assert _type("New-ScheduledTaskAction -Execute fake.exe") == PersistenceArtifactType.WINDOWS_SCHEDULED_TASK_REFERENCE

    def test_sc_create_command(self):
        result = classify_persistence_string("sc create FakeService")
        assert result.artifact_type == PersistenceArtifactType.WINDOWS_SERVICE_REFERENCE
        assert result.persistence_mechanism == "service_create_command"

    def test_createservice_api(self):
        result = classify_persistence_string("CreateServiceW")
        assert result.artifact_type == PersistenceArtifactType.WINDOWS_SERVICE_REFERENCE
        assert result.confidence == Confidence.LOW  # bare API name only

    def test_imagepath_value(self):
        result = classify_persistence_string(r"ImagePath=C:\Windows\fake.exe")
        assert result.artifact_type == PersistenceArtifactType.WINDOWS_SERVICE_REFERENCE
        assert result.persistence_mechanism == "service_image_path"


class TestWindowsWmi:
    def test_single_wmi_class_low_confidence(self):
        result = classify_persistence_string("__EventFilter")
        assert result.artifact_type == PersistenceArtifactType.WINDOWS_WMI_PERSISTENCE
        assert result.confidence == Confidence.LOW

    def test_multiple_wmi_classes_medium_confidence(self):
        result = classify_persistence_string("__EventFilter and CommandLineEventConsumer together")
        assert result.artifact_type == PersistenceArtifactType.WINDOWS_WMI_PERSISTENCE
        assert result.confidence == Confidence.MEDIUM
        assert "CONFIGURATION" in result.notes

    def test_bare_wmi_word_not_classified(self):
        assert _type("WMI") is None

    def test_subscription_namespace(self):
        assert _type(r"root\subscription") == PersistenceArtifactType.WINDOWS_WMI_PERSISTENCE


class TestLinuxSystemd:
    def test_systemd_unit_path(self):
        result = classify_persistence_string("/etc/systemd/system/fake-fixture.service")
        assert result.artifact_type == PersistenceArtifactType.LINUX_SYSTEMD_UNIT
        assert result.platform == "linux"

    def test_systemd_user_unit_path(self):
        result = classify_persistence_string("/home/test/.config/systemd/user/fake.service")
        assert result.persistence_mechanism == "systemd_user_unit_path"

    def test_systemd_unit_content(self):
        value = "[Unit]\nDescription=fake\n[Service]\nExecStart=/usr/bin/fake\n[Install]\nWantedBy=multi-user.target"
        result = classify_persistence_string(value)
        assert result.artifact_type == PersistenceArtifactType.LINUX_SYSTEMD_UNIT
        assert result.confidence == Confidence.HIGH
        assert "CONFIGURATION" in result.notes

    def test_systemctl_enable_command(self):
        assert _type("systemctl enable fake.service") == PersistenceArtifactType.LINUX_SYSTEMD_UNIT

    def test_systemctl_user_enable_command(self):
        assert _type("systemctl --user enable fake.service") == PersistenceArtifactType.LINUX_SYSTEMD_UNIT


class TestLinuxCron:
    def test_etc_cron_d_path(self):
        assert _type("/etc/cron.d/fake-fixture") == PersistenceArtifactType.LINUX_CRON

    def test_etc_crontab_path(self):
        assert _type("/etc/crontab") == PersistenceArtifactType.LINUX_CRON

    def test_cron_spool_path(self):
        assert _type("/var/spool/cron/crontabs/testuser") == PersistenceArtifactType.LINUX_CRON

    def test_crontab_edit_command(self):
        result = classify_persistence_string("crontab -e")
        assert result.artifact_type == PersistenceArtifactType.LINUX_CRON
        assert "COMMAND" in result.notes

    def test_bare_crontab_word_not_classified(self):
        assert _type("crontab") is None


class TestLinuxShellProfileAndAutostart:
    def test_bashrc_path(self):
        assert _type("/home/test/.bashrc") == PersistenceArtifactType.LINUX_SHELL_PROFILE

    def test_etc_profile_path(self):
        assert _type("/etc/profile") == PersistenceArtifactType.LINUX_SHELL_PROFILE

    def test_desktop_autostart_content(self):
        value = "[Desktop Entry]\nType=Application\nExec=/usr/bin/fake\nHidden=false"
        result = classify_persistence_string(value)
        assert result.artifact_type == PersistenceArtifactType.LINUX_AUTOSTART
        assert result.confidence == Confidence.HIGH

    def test_autostart_path_only(self):
        assert _type("/home/test/.config/autostart/fake.desktop") == PersistenceArtifactType.LINUX_AUTOSTART

    def test_rc_local(self):
        assert _type("/etc/rc.local") == PersistenceArtifactType.LINUX_INIT_SCRIPT

    def test_init_d_script(self):
        assert _type("/etc/init.d/fake-fixture") == PersistenceArtifactType.LINUX_INIT_SCRIPT


class TestLinuxSshAndLoader:
    def test_authorized_keys_path(self):
        assert _type("/home/test/.ssh/authorized_keys") == PersistenceArtifactType.LINUX_AUTHORIZED_KEYS_PATH

    def test_authorized_key_entry(self):
        value = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE test@fixture"
        result = classify_persistence_string(value)
        assert result.artifact_type == PersistenceArtifactType.LINUX_AUTHORIZED_KEY_ENTRY
        assert result.confidence == Confidence.HIGH

    def test_ld_preload_env(self):
        assert _type("LD_PRELOAD=/tmp/fake.so") == PersistenceArtifactType.LINUX_LOADER_PRELOAD

    def test_ld_so_preload_path(self):
        assert _type("/etc/ld.so.preload") == PersistenceArtifactType.LINUX_LOADER_PRELOAD


class TestRedaction:
    def test_short_value_fully_masked(self):
        assert redact_value("abc123") == "******"

    def test_long_value_partially_masked(self):
        redacted = redact_value(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run")
        assert "..." in redacted
        assert redacted != r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"


class TestFalsePositives:
    def test_normal_windows_path(self):
        assert _type(r"C:\Program Files\App\app.exe") is None

    def test_ordinary_run_word(self):
        assert _type("Run") is None
        assert _type("please run this program") is None

    def test_generic_service_word(self):
        assert _type("service") is None
        assert _type("this is a web service") is None

    def test_generic_task_word(self):
        assert _type("task") is None
        assert _type("the task completed successfully") is None

    def test_ordinary_powershell_command(self):
        assert _type("Get-Process | Where-Object Name -eq 'notepad'") is None

    def test_unrelated_registry_path(self):
        assert _type(r"HKCU\Software\MyApp\Settings\Theme") is None

    def test_documentation_mentioning_persistence(self):
        assert _type("This document describes persistence mechanisms used by malware.") is None

    def test_normal_systemd_documentation(self):
        assert _type("systemd is an init system used by many Linux distributions.") is None

    def test_ordinary_service_filename_without_path(self):
        assert _type("myapp.service") is None

    def test_normal_cron_word(self):
        assert _type("cron") is None

    def test_ordinary_shell_profile_word(self):
        assert _type("profile") is None
        assert _type("update your profile") is None

    def test_normal_ssh_key_without_full_shape(self):
        assert _type("ssh-rsa") is None
        assert _type("this looks like an ssh key but isn't") is None

    def test_ordinary_ld_preload_documentation(self):
        assert _type("LD_PRELOAD is a Linux dynamic linker feature.") is None

    def test_generic_systemctl_text(self):
        assert _type("systemctl status myapp") is None
        assert _type("systemctl") is None

    def test_url(self):
        assert _type("https://example.com/download/run.exe") is None

    def test_go_package_name(self):
        assert _type("os/exec") is None

    def test_source_code_comment(self):
        assert _type("// TODO: implement service discovery") is None

    def test_fixture_marker_string(self):
        assert _type("GOMEMFORENSICS_FIXTURE_STATIC_MARKER_39f1") is None

    def test_normal_process_command_line(self):
        assert _type("myapp --config=/etc/myapp/config.yaml --verbose") is None

    def test_empty_string(self):
        assert _type("") is None

    def test_over_length_bound(self):
        assert _type(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run" + "a" * MAX_PERSISTENCE_VALUE_LENGTH) is None

    def test_windows_pattern_never_matches_linux_platform(self):
        result = classify_persistence_string(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run")
        assert result.platform == "windows"

    def test_linux_pattern_never_matches_windows_platform(self):
        result = classify_persistence_string("/etc/systemd/system/fake.service")
        assert result.platform == "linux"
