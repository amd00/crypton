
#ifndef _CRYPROGRAPHER_H_
#define _CRYPROGRAPHER_H_

#include <sys/types.h>

typedef __uint8_t uint8;	//!< 8-битовое беззнаковое целое число.
typedef __uint32_t uint32;	//!< 32-битовое беззнаковое целое число.
typedef __uint64_t uint64;	//!< 64-битовое беззнаковое целое число.

typedef __int8_t int8;		//!< 8-битовое целое число.
typedef __int32_t int32;	//!< 32-битовое целое число.
typedef __int64_t int64;	//!< 64-битовое целое число.

const uint8 byteSize = 8;	//!< Количество битов в байте.

//==========================================================================//

//! Класс, реализующий криптографические функции по ГОСТ.
class Cryptographer
{
private:
	uint32 m_key[8];																//!< Ключ.
	uint8 m_replace_table[8][16];													//!< Таблица замен.

public:
	Cryptographer();																//!< Конструктор.
	Cryptographer(const Cryptographer &cr);											//!< Конструктор копирования.
	~Cryptographer();																//!< Деструктор.

	void init(bool _rand = true);													//!< Инициализация.

	bool simpleReplace(uint8 *_data, uint32 _size, bool _encoding) const;			//!< Алгоритм простой замены.
	bool gamming(uint8 *_data, uint32 _size, uint64 &S) const;						//!< Алгоритм гаммирования.
	bool gammingWF(uint8 *_data, uint32 _size, uint64 &S, bool _encoding) const;	//!< Алгоритм гаммирования с обратной связью.
	uint32 imiIns(uint8 *_data, uint32 _size) const;								//!< Алгоритм выработки имитовставки.

	void setKey(uint32 *_key);														//!< Установка ключа.
	void setReplaceTable(uint8 **_replace_table);									//!< Установка таблицы замен.

	Cryptographer &operator=(const Cryptographer &cr);								//!< Оператор присваивания.

private:
	uint64 cycle_32Z(uint64 _data) const;											//!< Реализация цикла 32-З.
	uint64 cycle_32R(uint64 _data) const;											//!< Реализация цикла 32-Р.
	uint64 cycle_16Z(uint64 _data) const;											//!< Реализация цикла 16-З.
	uint64 mainStep(uint64 _data, uint8 _key_num) const;							//!< Основной шаг криптопреобразования.
	uint64 pow(uint64 n, uint8 p) const;											//!< Возведение в степень.
	uint64 pow2(uint8 p) const;														//!< Степень двойки.
};

//==========================================================================//

#endif
