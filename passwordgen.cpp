
#include <string.h>
#include <stdlib.h>
#include <cmath>
#include <new>

using namespace std;

#include "passwordgen.h"

/*! \class PasswordGen
	Класс реализует генератор случайных последовательностей символов алфавита \e alphabeth.
	В качестве генератора случайных чисел используется класс \e PasswordGen.
	\par Пример:
	\code
	PasswordGen pg;
	// Генерируем пароль длиной 8 символов.
	char *pass = pg.nextPassword(8);
	// TODO
	delete [] pass;
	\endcode
*/

//==========================================================================//

char PasswordGen::alphabeth[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

//==========================================================================//

/*! Создаёт объект класса. Производится инициализация генератора случайных чисел \e rg.
*/
PasswordGen::PasswordGen() : rg(), seq_len(strlen(alphabeth) < 100 ? 1200 : 2400), curr_pos(seq_len)
{
	password_seq = new char[seq_len];
	memset(password_seq, 0, seq_len);
	rg.init();
}

//==========================================================================//

/*! Создаёт объект класса путём копирования свойств объекта \e pg.
	\param pg - объкт класса \e PasswordGen.
*/
PasswordGen::PasswordGen(const PasswordGen &pg) : rg(pg.rg), seq_len(pg.seq_len), curr_pos(pg.curr_pos)
{
	password_seq = new char[seq_len];
	memcpy(password_seq, pg.password_seq, seq_len);
}

//==========================================================================//

/*! Уничтожает объект класса.
*/
PasswordGen::~PasswordGen()
{
	delete [] password_seq;
	password_seq = NULL;
}

//==========================================================================//

/*! Генерирует случайную последовательность символов длины \e password_len. Для результата
	производится выделение памяти с помощью оператора \b new, поэтому после использования,
	память должна быть освобождена во избежание утечек.
	\param password_len - длна генерируемой последовательности.
	\returns Сгенерированную случайную последовательность символов алфавита.
*/
char *PasswordGen::nextPassword(uint32 password_len)
{
	char *res = new(nothrow) char[password_len + 1];
	if(!res)
		return NULL;
	memset(res, 0, password_len + 1);
	for(uint32 i = 0; i < password_len; i++)
		res[i] = getChar();
	return res;
}

//==========================================================================//

/*! Копирует свойства объекта \e pg.
	\param pg - объект класса \e PasswordGen.
*/
PasswordGen &PasswordGen::operator=(const PasswordGen &pg)
{
	rg = pg.rg;
	curr_pos = pg.curr_pos;
	seq_len = pg.seq_len;
	memcpy(password_seq, pg.password_seq, seq_len);
	return *this;
}

//==========================================================================//

/*! Берёт из последовательности \e password_seq очередной символ и увеличивает \e curr_pos.
	Если \e curr_pos превысил за границы размера \e password_seq, создаётся новая последовательность
	\e password_seq.
	\returns Очередной символ из \e password_seq.
*/
char PasswordGen::getChar()
{
	if(curr_pos == seq_len)
		createNewPasswordSeq();
	char res = password_seq[curr_pos];
	curr_pos++;
	return res;
}

//==========================================================================//

/*! Создание новой последовательности \e password_seq из символов алфавита \e alphabeth.
	После создание производится проверка качества последовательности и в случае необходимости
	цикл повторяется. Указатель \e curr_pos сбрасывается в \b 0.
*/
void PasswordGen::createNewPasswordSeq()
{
	do
	{
		for(uint32 i = 0; i < seq_len; i++)
			password_seq[i] = alphabeth[rg.nextInt8() % strlen(alphabeth)];
	}
	while(!isCurrentSeq());
	curr_pos = 0;
}

//==========================================================================//

/*! Проверка качества текущей последовательности \e password_seq путём её тестирования
	с помощью функции <em>test()</em>.
	\returns \b true - в случае успеха, \b false - иначе.
*/
bool PasswordGen::isCurrentSeq() const
{
	return test();
}

//==========================================================================//

/*! Проверка качества текущей последовательности \e password_seq.
	\returns \b true - в случае успеха, \b false - иначе.
*/
bool PasswordGen::test() const
{
	const uint32 M  = strlen(alphabeth);
	uint32 N = seq_len;
	uint32 m[M];
	memset(m, 0, sizeof(m));
	const float b1 = (N - 2.58 * sqrt(N * (M - 1.))) / M;
	const float b2 = (N + 2.58 * sqrt(N * (M - 1.))) / M;
	const float g1 = pow(sqrt(2. * M - 1.) - 2.33, 2) / 2.;
	const float g2 = pow(sqrt(2. * M - 1.) + 2.33, 2) / 2.;
	for(uint32 i = 0; i < M; i++)
	{
		for(uint32 j = 0; j < N; j++)
			if(password_seq[j] == alphabeth[i])
				m[i]++;
		if(m[i] < b1 || m[i] > b2)
			return false;
	}
	float hi2 = 0;
	for(uint32 i = 0; i < M; i++)
		hi2 += pow(m[i] - (float)N / M, 2) / ((float)N / M);
	if(hi2 < g1 || hi2 > g2)
		return false;
	return true;
}

//==========================================================================//
