
_hints_start = ORIGIN(REGION_HINTS);
_hints_length = 128M;
_lengths_of_hints_start = ORIGIN(REGION_HINTS);
_lengths_of_pubio_start = ORIGIN(REGION_PUBIO);
_pubio_start  = ORIGIN(REGION_PUBIO);             /* 0x20000000 */
_pubio_end    = ORIGIN(REGION_PUBIO) + 128M;      /* PUBIO grows upward */
_pubio_length = 128M;
_stack_start  = ORIGIN(REGION_PUBIO) + 256M;      /* stack grows downward */

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

  .pubio (NOLOAD): ALIGN(4)
  {
    *(.pubio .pubio.*);
  } > STACK_PUBIO

  .stack (NOLOAD) : ALIGN(4)
  {
    *(.stack .stack.*)
  } > STACK_PUBIO

  /* Define a section for runtime-populated EEPROM-like HINTS data */
  .hints (NOLOAD) : ALIGN(4)
  {
      *(.hints .hints.*);
  } > HINTS

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

  /* align to 256Mb boundary to ensure proper memory layout. */
  /* this reserves some padding up to the next power of 2 for .text, .sdata, .bss sections, ensuring there is no overlap with the heap. */
  /* NOTE 1: This works correctly **only** if the total size of .text + .rodata + .data + .bss does not exceed 256MB. */
  /* NOTE 2: This alignment **does not** affect the binary size.  */
    . = ALIGN(0x10000000);
    _sheap = .;
  } > RAM
}
