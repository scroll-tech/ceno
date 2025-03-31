
_stack_start = ORIGIN(REGION_STACK) + LENGTH(REGION_STACK);
_hints_start = ORIGIN(REGION_HINTS);
_hints_length = LENGTH(REGION_HINTS);
_lengths_of_hints_start = ORIGIN(REGION_HINTS);
_pubio_start = ORIGIN(REGION_PUBIO);
_pubio_length = LENGTH(REGION_PUBIO);
_lengths_of_pubio_start = ORIGIN(REGION_PUBIO);

SECTIONS
{
  .text :
  {
    KEEP(*(.init));
    . = ALIGN(4);
    *(.text .text.*);
  } > ROM

  .rodata : ALIGN(4)
  {
    *(.srodata .srodata.*);
    *(.rodata .rodata.*);
  } > ROM

  .data : ALIGN(4)
  {
    /* Must be called __global_pointer$ for linker relaxations to work. */
    PROVIDE(__global_pointer$ = . + 0x800);

    *(.sdata .sdata.*);
    *(.sdata2 .sdata2.*);
    *(.data .data.*);
  } > RAM

  .bss (NOLOAD) : ALIGN(4)
  {
    *(.sbss .sbss.*);
    *(.bss .bss.*);

  /* align 256Mb */
  /* assure once we do padding to next power of 2 for rom + sdata + bss */
  /* there is no overlap with heap */
  /* NOTE: this will not affect binary size */
    . = ALIGN(0x10000000);
    _sheap = .;
  } > RAM

  /* Define a section for runtime-populated EEPROM-like HINTS data */
  .hints (NOLOAD) : ALIGN(4)
  {
    *(.hints .hints.*);
  } > HINTS

  /* Define a section for public io data */
  .pubio (NOLOAD) : ALIGN(4)
  {
    *(.pubio .pubio.*);
  } > PUBIO
}
