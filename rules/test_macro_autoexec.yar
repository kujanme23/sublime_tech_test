rule Sublime_Test_Macro_Autoexec_With_Suspicious_Keywords
{
  meta:
    author = "You"
    description = "Detects Office macro indicators + autoexec entrypoints + common suspicious VBA keywords"

  strings:
    // Common VBA / macro artifacts
    $vb_attr   = "Attribute VB_Name" nocase
    $vba_proj  = "VBAProject" nocase
    $thisdoc   = "ThisDocument" nocase

    // Auto-execution entrypoints
    $autoopen  = "AutoOpen" nocase
    $docopen   = "Document_Open" nocase
    $workopen  = "Workbook_Open" nocase

    // Common suspicious keywords seen in malicious macros
    $createobj = "CreateObject" nocase
    $wshell    = "WScript.Shell" nocase
    $shell     = "Shell" nocase
    $powershell= "powershell" nocase
    $urldl     = "URLDownloadToFile" nocase
    $xmlhttp   = "XMLHTTP" nocase
    $winhttp   = "WinHttp" nocase

  condition:
    // Must look like VBA/macro content
    1 of ($vb_attr, $vba_proj, $thisdoc)
    and
    // Must include at least one auto-exec entrypoint
    1 of ($autoopen, $docopen, $workopen)
    and
    // And at least one suspicious capability keyword
    1 of ($createobj, $wshell, $shell, $powershell, $urldl, $xmlhttp, $winhttp)
}
