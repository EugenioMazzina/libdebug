//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2023-2024 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <stdio.h>
#include <stdlib.h>

void base_test(){
    asm volatile(
        "push %%rbp\n\t"
        "push %%rax\n\t"
        "xor %%rax, %%rax, %%rax\n\t"
        "xor %%rax, %%rax, %%rax\n\t"
        "xor %%rax, %%rax, %%rax\n\t"
        "pop %%rax\n\t"
        "pop %%rbp\n\t"
        :
        :
        : "rax"
    );
    base_test_2();
}

void base_test_2(){
    asm volatile(
        "push %%rbp\n\t"
        "nop\n\t"
        "pop %%rbp\n\t"
        :
        :
        :
    );
}

int main()
{
    printf("Provola\n");

    base_test();

    return EXIT_SUCCESS;
}