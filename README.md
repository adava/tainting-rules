# Execution and testing
To test the taint rules, run:

    cc -std=c99 tests/taint_tests.c `pkg-config --cflags --libs glib-2.0` -o taint_tests.o; ./taint_tests.

To test the shadow memory, run:

    cc -std=c99 tests/shadow_aux_tests.c `pkg-config --cflags --libs glib-2.0` -o shadow_aux_tests.o; ./shadow_aux_tests.o
