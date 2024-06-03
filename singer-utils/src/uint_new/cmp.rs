// TODO: document module
//  mostly holds comparison methods on the uint type

// what methods were implemented previously
// lt
// assert_lt
// assert_leq
// assert_eq
// assert_eq_range_values

// seems only 1 direction is enough, no need for lt and gt
// why lt then assert_lt but no leq only assert_leq
// will assume no need for it for now and wait until things break

// going to focus on assert methods
// assert_lt
// assert_leq
// assert_eq
// assert_eq_range_values (this feels weird)
//  feels like we should be able to convert the range values to uint
//  then run assert_eq on them
//  what is the problem with this?
