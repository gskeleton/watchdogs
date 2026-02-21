#ifndef PROCESS_H
#define PROCESS_H

#ifndef DOG_WINDOWS
extern char **environ;
#endif

long pawn_get_milisec();
void pawn_stage_trying(const char *stage, int ms);
void dog_serv_init(char *input_path, char *pawncc_path);
int dog_exec_pawn_process(char *pawncc_path,
							  char *input_path,
							  char *output_path);

#endif