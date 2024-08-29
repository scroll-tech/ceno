SECTIONS
{
  .text :
  {
    *(.text._start);
    *(.text .text.*);
  } > FLASH
}