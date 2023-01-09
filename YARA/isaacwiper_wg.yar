rule isaacwiper_wg {

	meta:
		author = "Ryan Estes"
		date = "2023-01-07"
		category = "Wiper"
		wiper = "ISAACWiper"
		description = "YARA rule for ISAACWiper, created for WatchGuard Wipers presentation."
		
		hash0 = 13037b749aa4b1eda538fda26d6ac41c8f7b1d02d83f47b0d187dd645154e033
		hash1 = 7bcd4ec18fc4a56db30e0aaebd44e2988f98f7b5d8c14f6689f650b4f11e16c0
		hash2 = abf9adf2c2c21c1e8bd69975dfccb5ca53060d8e1e7271a5e9ef3b56a7e54d9f
		hash3 = afe1f2768e57573757039a40ac40f3c7471bb084599613b3402b1e9958e0d27a
		
	strings:
		$s0 = "_Start@4"
		$s1 = "Tmd"
		$s2 = "Tmf"
		$s3 = "\\.\"
		$s4 = "PhysicalDrive"
		
		$dbg0 = "cleaner.dll"
		$dbg1 = "C:\Programata\log.txt"
		$dbg2 = "start erasing physical drives..."
		$dbg3 = "start erasing system physical drive..."
		$dbg4 = "start erasing system logical drive"
		$dbg5 = "getting drives..."
		$dbg6 = "physical drives:"
		$dbg7 = "-- system physical drive"
		$dbg8 = "-- physical drive"
		$dbg9 = "logical drives:"
		$dbg10 = "-- system logical drive:"
		$dbg11 = "-- logical drive:"
		$dbg12 = "-- FAILED"
		$dbg13 = "physical drive"
		$dbg14 = "-- start erasing logical drive"
		$dbg15 = "system physical drive -- FAILED"
	
	rule has_strings:
	{
		condition:
			(all of ($s*))
	}	
	rule has_dbg:
	{
		condition:
			(all of ($dbg*))
	}
	
	rule is_pe:
	{
		condition:
			pe.is_pe
	}
	
	rule is_dll:
	{
		condition:
			pe.characteristics & pe.DLL
	}	
	
	rule has_export:
	{
		condition:
			pe.exports("_Start@4")
	}	
	
	condition:
		(has_strings or has_dbg) and (is_pe or is_dll) and (has_export)
}
















