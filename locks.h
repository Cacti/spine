#define LOCK_CREW 0
#define LOCK_STATS 1

void	mutex_lock(int);
void	mutex_unlock(int);
int	mutex_trylock(int);
