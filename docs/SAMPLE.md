#### Yara
| Rule        | Description  | Offset      | Data        | Tags        |
|-------------|--------------|-------------|-------------|-------------|
| `Contains_PE_File` | Detect a PE file inside a byte sequence | `0x0` | &#34;MZ&#34; | [] |
| `maldoc_function_prolog_signature` |  | `0x1454` | &#34;U\x8b\xec\x81\xec&#34; | [] |
| `maldoc_structured_exception_handling` |  | `0x5a55` | &#34;d\xa1\x00\x00\x00\x00&#34; | [] |
| `maldoc_suspicious_strings` |  | `0x67ec` | &#34;CloseHandle&#34; | [] |
| `PEiD_00138_Armadillo_v1_71_` | [Armadillo v1.71] | `0x5a46` | &#34;U\x8b\xecj\xffh b@\x00h\xc6[@\x00d\xa1&#34; | [] |
| `PEiD_00497_dUP_v2_x_Patcher_____www_diablo2oo2_cjb_net_` | [dUP v2.x Patcher --&gt; www.diablo2oo2.cjb.net] | `0x4e` | &#34;This program cannot be ru&#34; | [] |
| `PEiD_00729_Free_Pascal_1_06_` | [Free Pascal 1.06] | `0x3a12` | &#34;\xc6\x05\xc0\x84@\x00O\xe8k\x04\x00\x00&#34; | [] |
| `PEiD_01101_Microsoft_Visual_C___v5_0_v6_0__MFC__` | [Microsoft Visual C&#43;&#43; v5.0/v6.0 (MFC)] | `0x5a46` | &#34;U\x8b\xecj\xffh b@\x00h\xc6[@\x00d\xa1\x00\x00\x00\x00P&#34; | [] |
| `PEiD_01108_Microsoft_Visual_C___v6_0_` | [Microsoft Visual C&#43;&#43; v6.0] | `0x5a46` | &#34;U\x8b\xecj\xffh b@\x00h\xc6[@\x00d\xa1\x00\x00\x00\x00Pd\x89%&#34; | [] |
| `PEiD_01110_Microsoft_Visual_C___v6_0_` | [Microsoft Visual C&#43;&#43; v6.0] | `0x5a46` | &#34;U\x8b\xecj\xffh b@\x00h\xc6[@\x00d\xa1\x00\x00\x00\x00Pd\x89%&#34; | [] |
| `PEiD_01125_Microsoft_Visual_C___` | [Microsoft Visual C&#43;&#43;] | `0x5a46` | &#34;U\x8b\xecj\xffh b@\x00h\xc6[@\x00d\xa1\x00\x00\x00\x00Pd\x89%&#34; | [] |
| `_dUP_v2x_Patcher__wwwdiablo2oo2cjbnet_` | dUP v2.x Patcher --&gt; www.diablo2oo2.cjb.net | `0x4e` | &#34;This program cannot be ru&#34; | [] |
| `_Microsoft_Visual_Cpp_` | Microsoft Visual C&#43;&#43; | `0x5a46` | &#34;U\x8b\xecj\xffh b@\x00h\xc6[@\x00d\xa1\x00\x00\x00\x00Pd\x89%&#34; | [] |
| `_Free_Pascal_v106_` | Free Pascal v1.06 | `0x3a12` | &#34;\xc6\x05\xc0\x84@\x00O\xe8k\x04\x00\x00&#34; | [] |
| `_Armadillo_v171_` | Armadillo v1.71 | `0x5a46` | &#34;U\x8b\xecj\xffh b@\x00h\xc6[@\x00d\xa1&#34; | [] |
| `_Microsoft_Visual_Cpp_v60_` | Microsoft Visual C&#43;&#43; v6.0 | `0x5a46` | &#34;U\x8b\xecj\xffh b@\x00h\xc6[@\x00d\xa1\x00\x00\x00\x00Pd\x89%&#34; | [] |
| `_Microsoft_Visual_Cpp_v50v60_MFC_` | Microsoft Visual C&#43;&#43; v5.0/v6.0 (MFC) | `0x5a46` | &#34;U\x8b\xecj\xffh b@\x00h\xc6[@\x00d\xa1\x00\x00\x00\x00P&#34; | [] |
> NOTE: **Data** truncated to 25 characters

