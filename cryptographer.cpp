
/*! \mainpage Библиотека crypton.
	Библиотека \e crypton содержит набор классов для работы с криптографическими функциями.
	Библиотека содержит в себе реализацию следующих классов:\n
	1. \e Cryptographer \n
	2. \e RandomGen \n
	3. \e PasswordGen \n
	\par
	Класс \e Cryptographer содержит набор методов, позволяющих выполнять криптографические
	преобразования данных согласно алгоритмам, описанным в <b>ГОСТ 28147-89</b>. Для его использования
	нужно подключить заголовочный файл \e cryptographer.h \code #include <cryptographer.h> \endcode
	\par
	Класс \e RandomGen содержит реализацию ПДСЧ (программного датчика случайных чисел). Данная
	реализация основана на алгоритме шифрования гаммирования с обратной связью, реализованном в
	классе \e Cryptographer. Для использования \e RandomGen нужно подключить заголовочный файл
	\e randomgen.h \code #include <randomgen.h> \endcode
	\par
	Класс \e PasswordGen реализует генератор случайных последовательностей символов (паролей).
	Данный генератор основан на ПДСЧ \e RandomGen.
	Для использования \e PasswordGen нужно подключить заголовочный файл
	\e passwordgen.h \code #include <passwordgen.h> \endcode
	\note Замечание:
	При сборке проекта, использующего данную библиотеку, необходимо указать компилятору опцию -lcrypton.
*/

#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "cryptographer.h"

/*! \class Cryptographer
	Класс содержит реализацию алгоритмов криптографического преобразования,
	описанных в <b>ГОСТ 28147-89</b>.
	Использование.
	Для использования класса необходимо создать объект \e Cryptographer и
	выполнить его инициализацию.
	\code
	Cryptographer cr;
	cr.init();
	\endcode
	После этого можно пользоваться функциями криптографического преобразования
	\e simpleReplace(), \e gamming(), \e gammingWF() и \e imiIns().\n
	\note
	Метод \e init() заполняет ключ и таблицу замен псевдослучайными значениями
	с использованием функции \e random(), которая является стандартной функцией языка C/C++.
	Начальным заполнением \e random() является текущее время.	Если необходимо использовать
	предопределённый ключ и таблицу замен, то вместо <em>init()</em> нужно использовать
	<em>setKey()</em> и <em>setReplaceTable()</em>.
*/

//==========================================================================//
/*! Создаёт объект класса \e Cryptographer.
*/
Cryptographer::Cryptographer() : m_key(), m_replace_table()
{

}

//==========================================================================//

/*! Создаёт объект класса \e Cryptographer путём копирования свойств объекта \e cr.
	\param cr - объект, копия которого создаётся.
*/
Cryptographer::Cryptographer(const Cryptographer &cr)
{
	for(uint8 i = 0; i < 8; i++)
	{
		m_key[i] = cr.m_key[i];
		for(uint8 j = 0; j < 16; j++)
			m_replace_table[i][j] = cr.m_replace_table[i][j];
	}
}

//==========================================================================//

/*! Уничтожает объект класса.
*/
Cryptographer::~Cryptographer()
{
}

//==========================================================================//

/*! Инициализирует ключ и таблицу замен. Если <em>_rand = false</em>, то заполнение
	происходит фиксированными значениями. Если же <em>_rand = true</em>, то ключ и таблица
	замен заполняются псевдослучайным образом (с помощью функции <em>random()</em>).
	\param _rand - если \b false, производится фиксированное заполнение, если \b true - псевдослучайное.
*/
void Cryptographer::init(bool _rand)
{
	if(_rand)
		srandom(time(NULL));
	else
		srandom(0);
	for(uint8 i = 0; i < 8; i++)
	{
		m_key[i] = random() % 0xffffffff;
		for(uint8 j = 0; j < 16; j++)
			m_replace_table[i][j] = random() % 0xf;
	}
}

//==========================================================================//

/*! Шифрование (расшифрование) данных в режиме простой замены. Преобразование производится
	по алгоритму простой замены, описанному в <b>ГОСТ 28147-89</b>. В данноми случае,
	длина данных в битах <b>должна быть кратна 64 (в байтах кратна 8)</b>, иначе алгоритм
	не будет работать.
	\par Пример:
	\code
	Cryptographer cr;
	char data[] = "12345678";
	int size = strlen(data);
	// Инициализация
	cr.init();
	// Зашифрование
	cr.simpleReplace(data, size, true);
	// Теперь в data содержатся зашифрованные данные.
	// Расшифрование
	cr.simpleReplace(data, size, false);
	// Теперь в data содержатся первоначальные данные, т.е. стока "12345678".
	\endcode
	\param _data - на входе шифруемые (расшифруемые) данные. В случае успешного выполнения преобразования,
	в \e _data записывается результат.
	\param _size - размер \e _data данных в байтах.
	\param _encoding - если \b true, производится зашифрование, если \b false - расшифрование.
	\returns \b true, если преобразование выполнено успешно, \b false - иначе.
*/
bool Cryptographer::simpleReplace(uint8 *_data, uint32 _size, bool _encoding) const
{
	if(_size % 8 != 0)
		return false;
	uint64 block;
	for(uint32 i = 0; i < _size; i += 8)
	{
		memcpy(&block, &_data[i], sizeof(block));
		if(_encoding)
			block = cycle_32Z(block);
		else
			block = cycle_32R(block);
		memcpy(&_data[i], &block, sizeof(block));
	}
	return true;
}

//==========================================================================//

/*! Шифрование (расшифрование) данных в режиме гаммирования. Преобразование производится
	по алгоритму гаммирования, описанному в <b>ГОСТ 28147-89</b>. В отличии от алгоритма
	простой замены, в данном случае можно преобразовывать данные произвольной длины. Причём
	путём вызова этого метода производятся зашифрование и расшифрование. Получаемая последовательность
	зависит от синхропосылки \e S. В процессе преобразования сихропосалка меняет своё значение.
	\par Пример:
	\code
	Cryptographer cr;
	char data[] = "12345678";
	int size = strlen(data);
	// Создание и копирование синхропосылки.
	int S = random();
	int S1 = S;
	// Инициализация
	cr.init();
	// Зашифрование

	cr.gamming(data, size, S);

	// Теперь в data содержатся зашифрованные данные, S содержит изменённую в процессе шифрования синхропосылку.

	// Расшифрование
	cr.gamming(data, size, S1);
	// Теперь в data содержатся первоначальные данные, т.е. стока "12345678".
	\endcode

	\param _data - на входе шифруемые (расшифруемые) данные. В случае успешного выполнения преобразования,
	в \e _data записывается результат.
	\param _size - размер \e _data в байтах.
	\param S - синхропосылка.
	\returns \b true, если преобразование выполнено успешно, \b false - иначе.
*/
bool Cryptographer::gamming(uint8 *_data, uint32 _size, uint64 &S) const
{
	S = cycle_32Z(S);
	uint32 S0 = S & 0x00000000ffffffffLL;
	uint32 S1 = (S & 0xffffffff00000000LL) >> (sizeof(uint32) * byteSize);
	uint32 C1 = 0x1010101;
	uint32 C2 = 0x1010104;
	uint32 i;
	uint64 block;
	for(i = 0; i + 8 < _size; i += 8)
	{
		S0 = (S0 + C1) % pow2(32);
		S1 = (S1 + C2 - 1) % (pow2(32) - 1) + 1;
		S = S0 | ((uint64)S1 << (sizeof(uint32) * byteSize));
		memcpy(&block, &_data[i], sizeof(block));
		block ^= cycle_32Z(S);
		memcpy(&_data[i], &block, sizeof(block));
	}
	uint32 tail_size = i == _size ? 0 : _size - i;
	if(tail_size)
	{
		block = 0;
		memcpy(&block, &_data[i], tail_size);
		block ^= cycle_32Z(S);
		memcpy(&_data[i], &block, tail_size);
	}
	return true;
}

//==========================================================================//

/*! Шифрование (расшифрование) данных в режиме гаммирования с обратной связью.
	Преобразование производится	по алгоритму гаммирования с обратной связью, описанному в <b>ГОСТ 28147-89</b>.
	В данном случае можно также преобразовывать данные произвольной длины. Получаемая последовательность
	зависит от синхропосылки \e S. В процессе преобразования сихропосалка меняет своё значение.
	\par Пример:
	\code
	Cryptographer cr;
	char data[] = "12345678";
	int size = strlen(data);
	// Создание и копирование синхропосылки.
	int S = random();
	int S1 = S;
	// Инициализация
	cr.init();
	// Зашифрование
	cr.gammingWF(data, size, S, true);
	// Теперь в data содержатся зашифрованные данные, S содержит изменённую в процессе шифрования синхропосылку.
	// Расшифрование
	cr.gammingWF(data, size, S1, false);
	// Теперь в data содержатся первоначальные данные, т.е. стока "12345678".
	\endcode
	\param _data - на входе шифруемые (расшифруемые) данные. В случае успешного выполнения преобразования,
	в \e _data записывается результат.
	\param _size - размер \e _data в байтах.
	\param S - синхропосылка.
	\param _encoding - если \b true, производится зашифрование, если \b false - расшифрование.
	\returns \b true, если преобразование выполнено успешно, \b false - иначе.
*/
bool Cryptographer::gammingWF(uint8 *_data, uint32 _size, uint64 &S, bool _encoding) const
{
	uint64 block;
	uint32 i;
	for(i = 0; i + 8 < _size; i += 8)
	{
		memcpy(&block, &_data[i], sizeof(block));
		uint64 tmp_block = block;
		block ^= cycle_32Z(S);
		memcpy(&_data[i], &block, sizeof(block));
		if(_encoding)
			S = block;
		else
			S = tmp_block;
	}
	uint32 tail_size = i == _size ? 0 : _size - i;
	if(tail_size)
	{
		block = 0;
		memcpy(&block, &_data[i], tail_size);
		block ^= cycle_32Z(S);
		memcpy(&_data[i], &block, tail_size);
	}
	return true;
}

//==========================================================================//

/*! Метод для выработки имитовставки для массива данных по алгоритму, описанному в <b>ГОСТ 28147-89</b>.
	Генерируется 32-битное целое число, используемое для контроля целостности данных.
	\param _data -данные, целостность которых нужно контролировать.
	\param _size - размер \e _data в байтах.
	\returns Сгенерированное число (имитовставку).
*/
uint32 Cryptographer::imiIns(uint8 *_data, uint32 _size) const
{
	uint64 S = 0, block;
	uint32 i;
	for(i = 0; i + 8 < _size; i += 8)
	{
		memcpy(&block, &_data[i], sizeof(block));
		S = cycle_16Z(S ^ block);
	}
	uint32 tail_size = i == _size ? 0 : _size - i;
	if(tail_size)
	{
		block = 0;
		memcpy(&block, &_data[i], tail_size);
		S = cycle_16Z(S ^ block);
	}
	return (S & 0x00000000ffffffffLL);
}

//==========================================================================//

/*! Устанавливает значение ключа в значение \e _key.
	\param _key - значение нового ключа.
*/
void Cryptographer::setKey(uint32 *_key)
{
	memcpy(m_key, _key, sizeof(m_key));
}

//==========================================================================//

/*! Устанавливает значения таблицы замен в значения таблицы \e _replace_table.
	\param _replace_table - значение новой таблицы замен.
*/
void Cryptographer::setReplaceTable(uint8 **_replace_table)
{
	for(uint8 i = 0; i < 8; i++)
		for(uint8 j = 0; j < 16; j++)
			m_replace_table[i][j] = _replace_table[i][j];
}

//==========================================================================//

/*! Копирует свойства объекта \e cr.
	\param cr - объект класса \e Cryptographer.
*/
Cryptographer &Cryptographer::operator=(const Cryptographer &cr)
{
	for(uint8 i = 0; i < 8; i++)
	{
		m_key[i] = cr.m_key[i];
		for(uint8 j = 0; j < 16; j++)
			m_replace_table[i][j] = cr.m_replace_table[i][j];
	}
	return *this;
}

//==========================================================================//

/*! Реализация цикл зашифрования 32-З, описанный в <b>ГОСТ 28147-89</b>.
	Производится преобразование 64-битного блока данных.
	\param _data - входной блок данных.
	\returns Результат преобразования.
*/
uint64 Cryptographer::cycle_32Z(uint64 _data) const
{
	uint64 data = _data;
	for(int8 i = 0; i < 3; i++)
		for(int8 j = 0; j < 8; j++)
			data = mainStep(data, j);
	for(int8 j = 7; j >= 0; j--)
		data = mainStep(data, j);

	uint32 N1 = data &  0x00000000ffffffffLL;
	uint32 N2 = (data & 0xffffffff00000000LL) >> (sizeof(uint32) * byteSize);

	uint64 res = pow((uint64)N1, sizeof(uint32) * byteSize) | N2;

	return res;
}

//==========================================================================//

/*! Реализация цикл расшифрования 32-Р, описанный в <b>ГОСТ 28147-89</b>.
	Производится преобразование 64-битного блока данных.
	\param _data - входной блок данных.
	\returns Результат преобразования.
*/
uint64 Cryptographer::cycle_32R(uint64 _data) const
{
	uint64 data = _data;
	for(int8 j = 0; j < 8; j++)
		data = mainStep(data, j);
	for(int8 i = 0; i < 3; i++)
		for(int8 j = 7; j >= 0; j--)
			data = mainStep(data, j);

	uint32 N1 = data &  0x00000000ffffffffLL;
	uint32 N2 = (data & 0xffffffff00000000LL) >> (sizeof(uint32) * byteSize);

	uint64 res = pow((uint64)N1, sizeof(uint32) * byteSize) | N2;

	return res;
}

//==========================================================================//

/*! Реализация цикла выработки имитовставки 16-З, описанный в <b>ГОСТ 28147-89</b>.
	Производится преобразование 64-битного блока данных.
	\param _data - входной блок данных.
	\returns Результат преобразования.
*/
uint64 Cryptographer::cycle_16Z(uint64 _data) const
{
	uint64 data = _data;
	for(uint8 i = 0; i < 2; i++)
		for(uint8 j = 0; j < 8; j++)
			data = mainStep(data, j);
	return data;
}

//==========================================================================//

/*! Реализация основного щага криптопреобразования.
	\param _data - входной блок данных.
	\param _key_num - номер элемента ключа, исользуемый для преобразования.
	\returns Преобразованный блок данных.
*/
uint64 Cryptographer::mainStep(uint64 _data, uint8 _key_num) const
{
	// Основной шаг криптопреобразования.
	
	// Шаг 0 основного шага. Определение исходных данных.
	uint32 N1 = _data &  0x00000000ffffffffLL;
	uint32 N2 = (_data & 0xffffffff00000000LL) >> (sizeof(uint32) * byteSize);
	
	// Шаг 1 основного шага. Сложение с ключом.
	uint32 S = ((uint64)N1 + m_key[_key_num]) % (pow2(sizeof(uint32) * byteSize) - 1);
	
	// Шаг 2 основного шага. Поблочная замена.
	uint32 mask[8] = {0x0000000f, 0x000000f0, 0x00000f00, 0x0000f000, 0x000f0000, 0x00f00000, 0x0f000000, 0xf0000000};
	uint32 tmp_res = 0;
	for(uint8 i = 0; i < 8; i++)
	{
		uint8 Si = (S & mask[i]) >> (i * 4);
		tmp_res += m_replace_table[i][Si] << (i * 4);
	}

	// Шаг 3 основного шага. Циклический сдвиг на 11 бит влево.
	S = (tmp_res >> ((sizeof(tmp_res) * byteSize) - 11)) | (tmp_res << 11);
	
	// Шаг 4 основного блока. Побитовое сложение.
	S = S ^ N2;
	
	// Шаг 5 основного блока. Сдвиг по цепочке.
	uint64 tmp_N1 = N1;
	uint64 res = (tmp_N1 << (sizeof(uint32) * byteSize)) | S;
	
	// Шаг 6 основного шага. Возврат результата.
	return res;
}

//==========================================================================//

/*! Метод, выполняющий операцию возведения в степень целого числа.
	\param n - основание степени.
	\param p - показатель степени.
	\returns \f$ n^p. \f$
*/
uint64 Cryptographer::pow(uint64 n, uint8 p) const
{
	return (n << p);
}

//==========================================================================//

/*! Метод, выполняющий операцию возведения в степень двойки.
	\param p - показатель степени.
	\returns \f$ 2^p. \f$
*/
uint64 Cryptographer::pow2(uint8 p) const
{
	return ((uint64)1 << p);
}

//==========================================================================//
