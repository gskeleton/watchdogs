native
	printf(const format[],
	     {Float,_}:...);

main() {
    printf("-------------");
    printf("Hello, World!");
    printf("* My Name is %s", "John");
    printf("* I am %d years old", 26);
    printf("* Pawn Compiler Version: 3.10.%d", __PawnBuild);
    printf("* Time: %s", __time);
    printf("* Date: %s", __date);
    printf("* File: %s", __file);
    printf("* Line: %d", __line);
    printf("-------------");
    }