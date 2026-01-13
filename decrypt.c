#include <stdio.h>

int	main(int ac, char **av)
{
	if (ac == 2)
	{
		int i = -1;
        while (av[1][++i])
            printf("%c", av[1][i] - i);
        printf("\n");
    }
}