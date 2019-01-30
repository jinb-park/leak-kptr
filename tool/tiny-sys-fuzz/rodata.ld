SECTIONS {
	.rodata : {
		rodata_start = ".";
		*(.rodata);
		rodata_end = ".";
	}
}
INSERT AFTER .text;
