
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "randomgen.h"

/*! \class RandomGen
	Реализация генератора случайных чисел, реализованного на основе криптографического алгоритма
	гаммирования с обратной связью, описанного в <b>ГОСТ 28147-89</b>. Для криптографических
	преобразований используется класс \e Cryptographer, реализующий алгоритмы их выше указанного ГОСТ.
	\par Пример:
	\code
	RandomGen rg;
	rg.init();
	int n = rg.nextInt32();
	\endcode
*/

//==========================================================================//

/*! Создаёт объект класса.
*/
RandomGen::RandomGen() : cs(0xA5DC00007F6BLL), S(0), rand_seq(), curr_pos(sizeof(rand_seq)), cr(), initialized(false)
{
	memset(rand_seq, 0, sizeof(rand_seq));
}

//==========================================================================//

/*! Создаёт объект класса путём копирования свойств объекта \e rg.
	\param rg - объкт класса \e RandomGen.
*/
RandomGen::RandomGen(const RandomGen &rg) : cs(rg.cs), S(rg.S), curr_pos(rg.curr_pos), cr(rg.cr), initialized(rg.initialized)
{
	memcpy(rand_seq, rg.rand_seq, sizeof(rand_seq));
}

//==========================================================================//

/*! Уничтожает объект класса.
*/
RandomGen::~RandomGen()
{
}

//==========================================================================//

/*! Инициализирует датчик случайных чисел. Производится вычисление текущей контрольной
	суммы алгоритма (это происходит на фиксированном начальном заполнении) и сравнение
	её с эталонной. В случае несовпадения КС, производится
	выход из приложения. После этого происходит инициализация начального заполнения
	алгоритма и проверка его качества. Если начальное заполнение не соответствует требованиям,
	цикл повторяется. 32 бита начального заполнения берётся из файла <b>/dev/urandom</b>,
	который является генератором случайных чисел, встроенным в ядро. Ещё 32 бита начального
	заполнения генерируются с помощью генератора псевдослучайных чисел (функция random()).
	Затем псевдослучайным образом заполняется массив, который будет шифроваться для получения
	последовательности случайных величин.
*/
void RandomGen::init()
{
	// Инициализация криптографического модуля с фиксированным заполнением для проверки КС.
	cr.init(false);
	// Проверка контрольной суммы алгоритма.
	if(cs != checkSum())
	{
		fprintf(stderr, "Check sum error\n");
		exit(1);
	}
	// Инициализация криптографического модуля.
	cr.init();
	FILE *urand_file = fopen("/dev/urandom", "r");
	if(!urand_file)
	{
		fprintf(stderr, "/dev/urandom fopen error: %s\n", strerror(errno));
		fclose(urand_file);
		exit(1);
	}

	// Инициализация начального заполнения.
	do
	{
		uint32 n1 = random();
		uint32 n2 = 0;
		if(fread(&n2, sizeof(n2), 1, urand_file) < 1)
		{
			fprintf(stderr, "/dev/urandom fread error: %s\n", strerror(errno));
			fclose(urand_file);
			exit(1);
		}
		S = n1 | ((uint64)n2 << (sizeof(uint32) * byteSize));
		cr.simpleReplace((uint8*)&S, sizeof(S), true);
	}
	while(!isCurrentS()); // Проверка корректности начального заполнения.
	fclose(urand_file);
	initialized = true;
	createNewRandSequence();
}

//==========================================================================//

/*! Генерация 8-битного целого числа.
	\returns 8-битное случайное число.
*/
uint8 RandomGen::nextInt8()
{
	if(curr_pos == sizeof(rand_seq))
		createNewRandSequence();
	uint8 res = rand_seq[curr_pos];
	curr_pos++;
	return res;
}

//==========================================================================//

/*! Генерация 32-битного целого числа.
	\returns 32-битное случайное число.
*/
uint32 RandomGen::nextInt32()
{
	uint32 res = 0;
	for(uint8 i = 0; i < sizeof(res); i++)
		res |= (uint32)nextInt8() << (i * byteSize);
	return res;
}

//==========================================================================//

/*! Генерация 64-битного целого числа.
	\returns 64-битное случайное число.
*/
uint64 RandomGen::nextInt64()
{
	uint64 res = 0;
	for(uint8 i = 0; i < sizeof(res); i++)
		res |= (uint64)nextInt8() << (i * byteSize);
	return res;
}

//==========================================================================//

/*! Копирует свойства объекта \e rg.
	\param rg - объект класса \e RandomGen.
*/
RandomGen &RandomGen::operator=(const RandomGen &rg)
{
	cs = rg.cs;
	S = rg.S;
	memcpy(rand_seq, rg.rand_seq, sizeof(rand_seq));
	curr_pos = rg.curr_pos;
	cr = rg.cr;
	initialized = rg.initialized;
	return *this;
}

//==========================================================================//

/*! Вычисление контрольной суммы алгоритма.
	\returns Вычисленная контрольная сумма.
*/
uint64 RandomGen::checkSum()
{
	S = 10781;
	for(uint32 i = 0; i < sizeof(rand_seq); i += sizeof(uint32))
	{
		uint32 tmp = random();
		memcpy(&rand_seq[i], &tmp, sizeof(tmp));
	}
	cr.gammingWF(rand_seq, sizeof(rand_seq), S, true);
	uint32 n = 100;
	uint32 S0 = 0, S1 = 0;
	for(uint32 i = 0; i < n; i++)
	{
		S0 = (S0 + nextInt32()) % ((1 << 16) - 1);
		S1 = (S1 + S0) % ((1 << 16) - 1);
	}
	uint32 Z0 = S0;
	uint32 Z1 = 65535 - S1;
	uint64 Z = Z0 | (uint64)Z1 << 32;
	return Z;
}

//==========================================================================//

/*! Проверка корректности начального заполнения \e S.
	\returns \b true - если \e S удовлетворяет требованиям, \b false - иначе.
*/
bool RandomGen::isCurrentS() const
{
	uint8 zero = 0;
	uint8 S_bits_size = sizeof(S) * 8;
	for(uint8 i = 0; i < S_bits_size; i++)
		if(S & (1 << i))
			zero++;
	float bound = S_bits_size * 0.12;
	uint8 diff = zero - (S_bits_size - zero);
	if(diff >= bound || diff <= -bound)
		return false;
	return true;
}

//==========================================================================//

/*! Создание последовательности для выработки случайных чисел. Создание производится
	путём шифрования \e rand_seq по алгоритму гаммирования с обратной связью. При
	этом проверяется качество полученной последовательности. Если результат не удовлетворяет
	требованиям, операция повторяется. При получении "качественной" последовательности
	иекущая позиция \e curr_pos сбрасывается в \b 0.
*/
void RandomGen::createNewRandSequence()
{
	FILE *urand_file = fopen("/dev/urandom", "r");
	if(!urand_file)
	{
		fprintf(stderr, "/dev/urandom fopen error: %s\n", strerror(errno));
		fclose(urand_file);
		exit(1);
	}
	uint32 tmp;
	do
	{
		// Создание шифруемой последовательности.
		for(uint32 i = 0; i < sizeof(rand_seq); i += sizeof(uint32))
		{
			if(!initialized)
				tmp = random();
			else if(fread(&tmp, sizeof(tmp), 1, urand_file) < 1)
			{
				fprintf(stderr, "/dev/urandom fread error: %s\n", strerror(errno));
				fclose(urand_file);
				exit(1);
			}

			memcpy(&rand_seq[i], &tmp, sizeof(tmp));
		}
		cr.gammingWF(rand_seq, sizeof(rand_seq), S, true);
	}
	while(!isCurrentSeq());
	fclose(urand_file);
	curr_pos = 0;	
}

//==========================================================================//

/*! Проверка качества текущей последовательности \e rand_seq путём последовательного тестирования
	на частоту битов (<em>test1()</em>), частоту четырёхбитовых последовательностей (<em>test2()</em>)
	и частоту битовых (<em>test3()</em>) серий.
	\returns \b true - в случае успеха, \b false - иначе.
*/
bool RandomGen::isCurrentSeq() const
{
	return (test1() && test2() && test3());
}

//==========================================================================//

/*! Проверка текущей последовательности \e rand_seq на частоту битов.
	\returns \b true - в случае успеха, \b false - иначе.
*/
bool RandomGen::test1() const
{
// 	qDebug() << "Проверка частоты битов...";
	uint32 begin_min_count = 9725;
	uint32 begin_max_count = 10275;
	uint32 seq_bits_size = sizeof(rand_seq) * byteSize;
	uint32 zero = 0;

	for(uint32 i = 0; i < seq_bits_size; i++)
		if(rand_seq[i / byteSize] & (1 << (i % byteSize)))
			zero++;
	bool res = false;
	if(zero >= begin_min_count && zero <= begin_max_count)
		res = true;
	return res;
}

//==========================================================================//

/*! Проверка текущей последовательности \e rand_seq на частоту четырёхбитовых последовательностей.
	\returns \b true - в случае успеха, \b false - иначе.
*/
bool RandomGen::test2() const
{
// 	qDebug() << "Проверка частоты четырёхбитовых последовательностей...";
	float min_bound = 2.16;
	float max_bound = 46.17;
	float X = 0;
	bool s[4] = {false};
	uint32 n_sum = 0;
	uint32 seq_bits_size = sizeof(rand_seq) * byteSize;
	for(uint32 i = 0; i < 16; i++)
	{
		s[0] = i & 1;
		s[1] = i & 2;
		s[2] = i & 4;
		s[3] = i & 8;
		uint32 n = 0;
		for(uint32 j = 0; j < seq_bits_size; j += 4)
		{
			bool bit0 = rand_seq[j / byteSize] & (1 << (j % byteSize));
			bool bit1 = rand_seq[(j + 1) / byteSize] & (1 << ((j + 1) % byteSize));
			bool bit2 = rand_seq[(j + 2) / byteSize] & (1 << ((j + 2) % byteSize));
			bool bit3 = rand_seq[(j + 3) / byteSize] & (1 << ((j + 3) % byteSize));

			if(bit0 == s[0] && bit1 == s[1] && bit2 == s[2] && bit3 == s[3])
				n++;
		}
		n_sum += n * n;
	}
	X = (16. / 5000.) * (float)n_sum - 5000.;
	bool res = false;
	if(X >= min_bound && X <= max_bound)
		res = true;
	return res;
}

//==========================================================================//

/*! Проверка текущей последовательности \e rand_seq на частоту битовых серий.
	\returns \b true - в случае успеха, \b false - иначе.
*/
bool RandomGen::test3() const
{
// 	qDebug() << "Проверка частоты битовых серий...";
	uint32 min_bounds[6] = {2343, 1135, 542, 251, 111, 111};
	uint32 max_bounds[6] = {2657, 1365, 708, 373, 201, 201};
	uint32 seq_bits_size = sizeof(rand_seq) * byteSize;
	for(uint32 n = 0; n < 6; n++)
	{
		uint32 count0 = 0;
		uint32 count1 = 0;
		for(uint32 i = 1; i < seq_bits_size;)
		{
			uint32 bit_count = 0;
			bool biti;
			bool biti_1;
			do
			{
				biti = rand_seq[i / byteSize] & (1 << (i % byteSize));
				biti_1 = rand_seq[(i - 1) / byteSize] & (1 << ((i - 1) % byteSize));
				bit_count++;
				i++;
			}
			while(i < seq_bits_size && biti == biti_1);
			if(bit_count > 26)
				return false;
			if(bit_count == n + 1 || (bit_count >= n + 1 && n + 1 == 6))
				(biti_1 ? count1 : count0)++;
		}
		if(count0 < min_bounds[n] || count0 > max_bounds[n] ||
				 count1 < min_bounds[n] || count1 > max_bounds[n])
			return false;
	}
	return true;
}

//==========================================================================//
