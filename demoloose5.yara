rule troloosedemo5strings
{
         meta: 
		   author="vashnavi"
		   malware="trojan sample"
		   
		   strings:
		           $a="NTI__DsOOBcxCUeVlNUDRmn9afcA_"
                           $b="NTI__F8OvqlxXyGXRSiK9c1fCDVw_"			 
                           $c= "NTI__g1w83cyyBYiVU9c8WEJWnjQ_"
			 
			 
			 condition:
			  ($a and $b and $c)
			 
} 