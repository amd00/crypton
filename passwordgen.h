
#ifndef _PASSWORDGEN_H_
#define _PASSWORDGEN_H_

#include "randomgen.h"

//==========================================================================//

//! Класс генератора паролей.
class PasswordGen
{
private:
	static char alphabeth[];						//!< Алфавит.
	RandomGen rg;									//!< Генератор случайных чисел.
	char *password_seq;								//!< Текущая последовательность для выработки паролей.
	uint32 seq_len;									//!< Длина последовательности \e password_seq.
	uint32 curr_pos;								//!< Текущая позиция в \e password_seq.

public:
	PasswordGen();									//!< Конструктор.
	PasswordGen(const PasswordGen &pg);				//!< Конструктор копирования.
	~PasswordGen();									//!< Деструктор.

	char * nextPassword(uint32 password_len);		//!< Генерация пароля длиной \e password_len.

	PasswordGen &operator=(const PasswordGen &pg);	//!< Оператор присваивания.

private:
	char getChar();									//!< Получение очередного символа из последовательности \e password_seq.
	void createNewPasswordSeq();					//!< Создание новой последовательности \e password_seq.
	bool isCurrentSeq() const;						//!< Проверка корректности текущей последовательности \e password_seq.
	bool test() const;								//!< Проверка качества последовательности \e password_seq.
};

//==========================================================================//

#endif
