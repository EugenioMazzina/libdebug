//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2023-2024 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <stdio.h>
#include <stdlib.h>

void inner(int a, int i){
    a=a+i;
}

void base_test(){
    int a=0;
    for(int i=0; i<10; i++){
        a++;
        printf("a = %d\n", a);
        inner(a,i);
    }
}

int main()
{
    base_test();

    return EXIT_SUCCESS;
}