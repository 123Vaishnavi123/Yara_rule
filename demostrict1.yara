import "hash"
rule Backdoor1Static
{

	meta:
		description: "this rule is to detect backdoor"
        condition:
                hash.md5(0, filesize)=="48cd89827939b3a8976d9bb0993bc338"
}