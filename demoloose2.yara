rule Backdemo2strings
{
         meta: 
		     owner="vaishnavi"
		     description="backdoor sample"
		   
      strings:
		    
		    $a="|$x"
		     
                    $b= "|$T"
		   
		    $c= "T$1"
		 		 
    condition:
		
		($a and $b and $c)
						 
}
