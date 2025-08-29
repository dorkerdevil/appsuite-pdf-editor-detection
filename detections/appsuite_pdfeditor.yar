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
        (hash.sha256(0, filesize) == "fde67ba523b2c1e517d679ad4eaf87925c6bbf2f171b9212462dc9a855faa34b" or
         hash.sha256(0, filesize) == "b3ef2e11c855f4812e64230632f125db5e7da1df3e9e34fdb2f088ebe5e16603" or
         hash.sha256(0, filesize) == "6022fd372dca7d6d366d9df894e8313b7f0bd821035dd9fa7c860b14e8c414f2" or
         hash.sha256(0, filesize) == "da3c6ec20a006ec4b289a90488f824f0f72098a2f5c2d3f37d7a2d4a83b344a0" or
         hash.sha256(0, filesize) == "cb15e1ec1a472631c53378d54f2043ba57586e3a28329c9dbf40cb69d7c10d2c" or
         hash.sha256(0, filesize) == "956f7e8e156205b8cbf9b9f16bae0e43404641ad8feaaf5f59f8ba7c54f15e24" or
         hash.sha256(0, filesize) == "104428a78aa75b4b0bc945a2067c0e42c8dfd5d0baf3cb18e0f6e4686bdc0755") or
        any of ($pdfeditor_js, $utilityaddon_node, $user_agent, $c2_1, $c2_2, $c2_3, $c2_4, $log1, $log0)
}
}
