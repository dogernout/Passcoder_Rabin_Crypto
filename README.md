# Passcoder_Rabin_Crypto
Encryption of passwords using Rabin's cryptosystem and signing a public key with RSA.
Содержание архива:

passcoder.py
primes_mod.txt
private_key_RSA.txt
public_key_RSA.txt
Passcoder.py
При запуске основной программы появляется меню, в котором есть 3 функции: регистрация
пользователя, авторизация пользователя с дальнейшей возможностью шифрования,
расшифрования паролей и отображения общей базы, состоящей из описания и самих
паролей в зашифрованном виде (которые в дальнейшем можно расшифровать), а также
третья функция, состоящая в изменении подписи программы.

Primes_mod.txt
Дополнительный текстовый файл, содержащий простые числа в диапазоне от 1000 до
1 05000. Требуется для построения открытого ключа подписи программы.

Private_key_RSA.txt
Данный текстовый файл содержит исходный открытый ключ программы. После запуска
программы, его можно заменить. Предполагается, что это может сделать только
аффилированное лицо, иначе всем ранее зарегистрированным пользователям в дальнейшем
будет отказано в доступе и им придется перерегистрироваться.

Public_key_RSA.txt
Данный текстовый файл содержит исходный секретный ключ программы. Его также можно
заменить.

Режим регистрации пользователя.
В меню программы нужно выбрать “ 1 ” и следовать инструкциям.

Режим шифрования пароля.
Данный режим доступен пользователю только после предварительной авторизации, в
которой необходимо указать имя пользователя, пароль и путь к секретному ключу
пользователя. После проверки появится возможность зашифровать пароль, если ввести
правильный открытый ключ.

Режим расшифрования пароля.
Данный режим также доступен только после предварительной авторизации пользователя.
Необходимо в основном меню выбрать “ 2 ”, пройти процесс аутентификации, ввести путь к
отрытому ключу (если до этого не вводили) и пропустить этап добавления паролей, выбрав
нужный пункт меню.

Стойкость в 80 бит гарантируется благодаря большим генерируемым простым
числам для криптосистемы Рабина. Для генерации таких чисел был использован тест на
простоту Миллера – Рабина с количеством раундов, равным 100. Это число было выбрано
как округление log 2 𝑛, где 𝑛 – проверяемое на простоту число.

Поскольку при расшифровании сообщения появляются 4 возможных претендента,
исходный текст пароля был модернизирован на основе открытого ключа пользователя
путем добавления к началу сообщения последней цифры ключа, а к концу сообщения –
предпоследней цифры.

Возможные уязвимости:

Помимо сделанного, предполагалось добавить хеширование для защиты баз данных
пользователей и ключей программы.