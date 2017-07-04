pythales
========

A primitive implementation of Thales HSM (hardware security module) simulator. Only the basic (the most popular) HSM commands are implemented:

- BU - Generate a Key check value 
- CA - Translate PIN from TPK to ZPK 
- CY - Verify CVV/CSC
- DC - Verify PIN
- EC - Verify an Interchange PIN using ABA PVV method
- HC - Generate a TMK, TPK or PVK
- NC - Diagnostics information

Usage:
 >>> from pythales.hsm import HSM
 >>> hsm = HSM(header='SSSS', debug=True, skip_parity=True)
 >>> hsm.run()
 LMK: DEAFBEEDEAFBEEDEAFBEEDEAFBEEDEAF
 Firmware version: 0007-E000
 Message header: SSSS
 Listening on port 1500
 Connected client: 192.168.56.101:50010
 17:59:49.278803 << 8 bytes received from 192.168.56.101:50010: 
	00 06 53 53 53 53 4e 43                                 ..SSSSNC
 17:59:49.279338 >> 35 bytes sent to 192.168.56.101:50010:
 	00 21 53 53 53 53 4e 44 30 30 46 34 45 44 43 38         .!SSSSND00F4EDC8
 	44 45 42 36 37 46 36 45 32 38 30 30 30 37 2d 45         DEB67F6E280007-E
	30 30 30                                                000
	[Response Code   ]: [ND]
	[Error Code      ]: [00]
	[LMK Check Value ]: [F4EDC8DEB67F6E28]
	[Firmware Version]: [0007-E000]
 18:01:13.089485 << 108 bytes received from 192.168.56.101:50010: 
	00 6a 53 53 53 53 44 43 55 43 34 45 44 35 39 37         .jSSSSDCUC4ED597
	45 45 30 43 39 36 39 37 31 30 34 45 44 33 39 39         EE0C9697104ED399
	42 45 36 46 38 42 38 37 32 37 33 33 36 44 35 30         BE6F8B8727336D50
	43 34 37 31 32 38 44 37 31 30 44 46 34 35 30 42         C47128D710DF450B
	43 42 32 43 36 34 36 31 42 37 39 33 41 45 36 32         CB2C6461B793AE62
	44 46 43 38 44 32 34 32 36 30 31 34 30 37 30 30         DFC8D24260140700
	30 30 30 30 30 31 30 31 33 38 34 33                     000001013843	
	[TPK                  ]: [UC4ED597EE0C9697104ED399BE6F8B872]
	[PVK Pair             ]: [7336D50C47128D710DF450BCB2C6461B]
	[PIN block            ]: [793AE62DFC8D2426]
	[PIN block format code]: [01]
	[Account Number       ]: [407000000010]
	[PVKI                 ]: [1]
	[PVV                  ]: [3843]
	DEBUG: Decrypted pinblock: 0412748FFFFFFFEF
 18:01:13.090230 >> 10 bytes sent to 192.168.56.101:50010:
	00 08 53 53 53 53 44 44 30 30                           ..SSSSDD00
	[Response Code]: [DD]
	[Error Code   ]: [00]
 18:01:13.104389 << 68 bytes received from 192.168.56.101:50010: 
	00 42 53 53 53 53 43 59 55 31 43 31 45 42 31 30         .BSSSSCYU1C1EB10
	39 30 36 38 31 43 43 39 45 36 30 30 33 45 30 35         90681CC9E6003E05
	32 31 37 43 37 30 37 37 45 36 34 30 34 31 37 34         217C7077E6404174
	30 37 30 30 30 30 30 30 30 31 30 34 3b 31 37 31         070000000104;171
	32 32 30 31                                             2201
	[CVK                   ]: [U1C1EB1090681CC9E6003E05217C7077E]
	[CVV                   ]: [640]
	[Primary Account Number]: [4174070000000104]
	[Expiration Date       ]: [1712]
	[Service Code          ]: [201]
 18:01:13.104979 >> 10 bytes sent to 192.168.56.101:50010:
	00 08 53 53 53 53 43 5a 30 30                           ..SSSSCZ00
	[Response Code]: [CZ]
	[Error Code   ]: [00]

You may also check examples_ for more sophisticated HSM server implementation with some features like command line options parsing etc. The application works as server that may simultaneously serve only one connected client.

.. _examples: https://github.com/timgabets/pythales/tree/master/examples