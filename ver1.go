package main //главный исполняемый пакет main

import ( // подключаемые пакеты
	"encoding/json" // кодирование и декодирование json
	"log"           // для ошибок
	"net/http"      // пакет http предоставляет реализации HTTP-клиента и сервера
	"strings"       // пакет для строк
	"sync"

	"github.com/gorilla/mux" //пакет gorilla/mux реализует маршрутизатор и диспетчер запросов для сопоставления входящих запросов с соответствующим обработчиком
)

type Student struct { //Структура объекта Student
	ID         string `json:"id"`
	Firstname  string `json:"firstname"`
	Lastname   string `json:"lastname"`
	Patronymic string `json:"patronymic"`
	Gruppa     string `json:"gruppa"`
	Phone      string `json:"phone"`
	Grade      string `json:"grade"`
}

type User struct { // Структура для представления пользователя
	Username string `json:"username"`
	Password string `json:"password"`
}

type Token struct { // Структура для представления токена
	Token string `json:"token"`
}

var students []Student //Срез студентов (поидее массив ток безразмерный)

var users = map[string]string{ // Мапа для хранения пользователей (ключ + значение)
	"admin": "adminpassword",
}

var tokens = map[string]string{} // Мапа для хранения токенов (ключ + значение)

func authenticate(username, password string) (bool, string) { // Функция для аутентификации пользователя
	storedPassword, ok := users[username] //ищется пароль в мапе users по ключу username возвращая пароль если найден и логическое значение найден или нет
	if !ok {                              //если не найден пользователь вернуть false и пустой токен
		return false, ""
	}
	if password != storedPassword { //если найден пользователь но пароль не совпадает вернуть false и пустой токен
		return false, ""
	}
	token := generateToken(username) //выполнить функцию генерации токена и его возврат
	return true, token               //если аутендификация прошла успешно то из функции вовзращается true и сам токен
}

func generateToken(username string) string { // Функция для генерации токена доступа
	// В реальном приложении здесь должен быть более безопасный механизм генерации токена
	token := "mockedTokenFor" + username
	_mux.Lock()
	defer _mux.Unlock()                                             //"генерации токена " mockedTokenFor + имя пользователя
	tokens[token] = username                                        // добавить токен в мапу токенов (токен как ключ имя пользователя как значение)
	log.Printf("Generated token: %s for user: %s", token, username) // Для отлвдуи - вывод в консоль сгенерированный токен для какого пользователя
	return token                                                    // возвращает токен
}

func getStudents(w http.ResponseWriter, r *http.Request) { //функция отобразить всех студентов
	w.Header().Set("Content-Type", "application/json") //устанавливает заголовок для ответа - чтоб правильно определить json
	json.NewEncoder(w).Encode(students)                //преобразуем данные в json
}

func getStudent(w http.ResponseWriter, r *http.Request) { //функция отобразить студента который нужен по id в строке
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)           //r - информация о запросе от клиента, возвращаем переменные маршрута для текущего запроса(нам нужен id)
	for _, item := range students { //ищем по id в в нашем срезе студента так как нам не нужен индекс а только сам студент то ставим _
		if item.ID == params["id"] {
			json.NewEncoder(w).Encode(item)
			return
		}
	}
	json.NewEncoder(w).Encode(&Student{})
}

func createStudent(w http.ResponseWriter, r *http.Request) { //функция создания студента
	w.Header().Set("Content-Type", "application/json")
	var student Student
	_ = json.NewDecoder(r.Body).Decode(&student) //декодируем информацию о запросе, т.е. данные студента которые прислал клиент
	students = append(students, student)         //добавление в срез студента(куда добавить, кого добавить)
	json.NewEncoder(w).Encode(student)
}

func updateStudent(w http.ResponseWriter, r *http.Request) { //функция обновления данных о студенте
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)               //r - информация о запросе от клиента, возвращаем переменные маршрута для текущего запроса(нам нужен id)
	for index, item := range students { //ищем по id в в нашем срезе студента
		if item.ID == params["id"] {
			students = append(students[:index], students[index+1:]...) //удаляем из среза студента которого надо изменить(в срез добавляется те кто был до индекса студента и после но не сам с этим индексом)
			var student Student                                        //дальше все тоже самое что и в создании студента только id берется старый
			_ = json.NewDecoder(r.Body).Decode(&student)
			student.ID = params["id"]
			students = append(students, student)
			json.NewEncoder(w).Encode(student)
			return
		}
	}
	json.NewEncoder(w).Encode(students)
}

func deleteStudent(w http.ResponseWriter, r *http.Request) { //функция удаления студента
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)               //r - информация о запросе от клиента, возвращаем переменные маршрута для текущего запроса(нам нужен id)
	for index, item := range students { //ищем по id в в нашем срезе студента
		if item.ID == params["id"] {
			students = append(students[:index], students[index+1:]...) //удаляем из среза студента которого надо изменить(в срез добавляется те кто был до индекса студента и после но не сам с этим индексом)
			break
		}
	}
	json.NewEncoder(w).Encode(students)
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc { // Функция для проверки аутентификации пользователя с использованием токена
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization") // проверка шапки авторизации
		if authHeader == "" {                       //если не прописана шапка авторизации
			http.Error(w, "Authorization header is missing", http.StatusUnauthorized)
			return
		}
		// Ожидаем формат "Bearer {token}"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" { //если не формат Bearer {token}
			http.Error(w, "Authorization header format must be Bearer {token}", http.StatusUnauthorized)
			return
		}
		token := parts[1] //выбираем токен из среза [0] это Bearer [1] токен
		if !chek(token) { //если ненайден токен
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			log.Printf("Invalid token received: %s", token) // Для отладки - вывод ошибки если токен не верный или не найден (в консоль и пользователю)
			return
		}
		// Для отладки - выводит в консоль что авторизован пользователь с таким то токеном и именем
		// Пользователь аутентифицирован, продолжаем выполнение обработчика
		next.ServeHTTP(w, r)
	}
}

var _mux sync.Mutex

func chek(token string) bool {
	_mux.Lock()
	defer _mux.Unlock()
	username, ok := tokens[token] //ищем в мапе токенов токен который ввел пользователь (ключ токен значение имя пользователя)
	if !ok {
		return false
	}
	log.Printf("Authenticated user: %s with token: %s", username, token)
	return true
}

func loginHandler(w http.ResponseWriter, r *http.Request) { // Обработчик для аутентификации пользователя и выдачи токена
	w.Header().Set("Content-Type", "application/json")
	var user User
	_ = json.NewDecoder(r.Body).Decode(&user)                          //сохранение в user логина и пароля введенных пользователем
	authenticated, token := authenticate(user.Username, user.Password) //сначала обрабатывается функция аутентификации пользователя и возращается прошел ли ааутентификацию пользователь и сам токен
	if !authenticated {                                                //если аутентификация пользователя false - провалилась
		http.Error(w, "Invalid credentials", http.StatusUnauthorized) //Неверные учетные данные
		return
	}
	response := Token{Token: token} //отправляет токен пользователю
	json.NewEncoder(w).Encode(response)
}

func main() {
	r := mux.NewRouter() //создание маршрутизации используя пакет gorilla/mux
	students = append(students, Student{ID: "1", Firstname: "Никита", Lastname: "Грачев", Patronymic: "Андревич", Gruppa: "зцис-27м", Phone: "888888", Grade: "5"})
	students = append(students, Student{ID: "2", Firstname: "Иван", Lastname: "Иванов", Patronymic: "Иванович", Gruppa: "ДСИТ-17", Phone: "84948", Grade: "5"})
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/students", authMiddleware(getStudents)).Methods("GET")     //HandleFunc() указывает маршруты для обработки, первый параметр - маршрут который нужно обработать,
	r.HandleFunc("/students/{id}", authMiddleware(getStudent)).Methods("GET") // второй параметр - функция которая будет обрабатывать запрос
	r.HandleFunc("/students", authMiddleware(createStudent)).Methods("POST")  // а так же после точки к какому методу относится
	r.HandleFunc("/students/{id}", authMiddleware(updateStudent)).Methods("PUT")
	r.HandleFunc("/students/{id}", authMiddleware(deleteStudent)).Methods("DELETE")

	log.Fatal(http.ListenAndServe(":8000", r)) //слушает сетевой адресс и обрабатывает запросы, r как раз указывает как обрабатывать
}
