#include <stdio.h>

int main(int argc, char **argv)
{
    long a = 42;
    long b = 21;

    a += 21;
    b -= 21;
    a += b;
    b -= a;
    a = a + b;
    b = a - b;
    a = -a;
    b = -b;
    b = -a;
    a = -b;
    --b;
    ++a;

    printf("%d\n%d\n", a, b);
    return 0;
}
