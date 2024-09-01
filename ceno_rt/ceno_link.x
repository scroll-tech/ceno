SECTIONS
{
  .text :
  {
    *(.init);
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
    *(.sdata .sdata.*);
    *(.sdata2 .sdata2.*);
    *(.data .data.*);
  } > RAM

  .bss (NOLOAD) : ALIGN(4)
  {
    *(.sbss .sbss.*);
    *(.bss .bss.*);
  } > RAM
}