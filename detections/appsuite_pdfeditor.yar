rule AppSuite_PDFEditor_Backdoor {
    meta:
        description = "Detects AppSuite PDF Editor backdoor files and strings"
        author = "dorkerdevil"
        date = "2025-08-29"
    strings:
        $pdfeditor_js = "pdfeditor.js"
        $utilityaddon_node = "UtilityAddon.node"
        $user_agent = "PDFFusion/93HEU7AJ"
        $c2_1 = "appsuites.ai"
        $c2_2 = "sdk.appsuites.ai"
        $c2_3 = "on.appsuites.ai"
        $c2_4 = "log.appsuites.ai"
        $log1 = "LOG1"
        $log0 = "LOG0"
    condition:
        any of ($pdfeditor_js, $utilityaddon_node, $user_agent, $c2_1, $c2_2, $c2_3, $c2_4, $log1, $log0)
}
