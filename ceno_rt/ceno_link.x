
_stack_start = ORIGIN(REGION_STACK) + LENGTH(REGION_STACK);
_hints_start = ORIGIN(REGION_HINTS);
_hints_length = LENGTH(REGION_HINTS);
_lengths_of_hints_start = ORIGIN(REGION_HINTS);

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

    . = ALIGN(4);
    _sheap = .;
  } > RAM

  /* Define a section for runtime-populated EEPROM-like HINTS data */
  .hints (NOLOAD) : ALIGN(4)
  {
    *(.hints .hints.*);
  } > HINTS
}
