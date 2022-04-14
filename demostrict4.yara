import "hash"

rule Backdoor3Static 

 {
 
    meta:
	
	    desription = "this rule is to detect malware "
     
	 
	     condition:
		 hash.md5(0, filesize) == "2a9d0d06d292a4cbbe4a95da4650ed54"
 
 }