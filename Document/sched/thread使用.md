### c++的thread库
```shell
C++ Standard Library <thread>
├── 线程创建与管理
│   ├── std::thread          : 创建线程对象
│   ├── join()               : 等待线程完成
│   ├── detach()             : 将线程设为分离状态
│   └── hardware_concurrency(): 返回系统中可并发执行的线程数量
│
├── 线程同步与互斥
│   ├── std::mutex           : 互斥锁
│   │   ├── lock()           : 显式加锁
│   │   ├── unlock()         : 显式解锁
│   │   └── try_lock()       : 尝试加锁（非阻塞）
│   ├── std::lock_guard      : 自动管理互斥锁
│   ├── std::unique_lock     : 灵活管理锁，支持手动锁定/解锁
│   └── std::condition_variable : 条件变量，用于等待或通知线程
│
├── 线程通信
│   ├── std::future          : 获取异步操作结果
│   ├── std::promise         : 提供值给`future`
│   └── std::async           : 启动异步任务并返回`future`
│
├── 线程局部存储
│   └── thread_local         : 定义线程局部存储变量
│
├── 原子操作
│   └── std::atomic          : 提供原子操作，避免锁
│       ├── store()          : 存储值
│       ├── load()           : 加载值
│       └── compare_exchange : 比较并交换
│
├── 线程异常处理
│   └── std::terminate       : 捕获未处理异常并终止线程
│
└── 线程ID与状态
    ├── std::this_thread::get_id()  : 获取当前线程ID
    ├── std::thread::get_id()       : 获取线程对象的ID
    ├── std::this_thread::sleep_for(): 休眠指定时间
    └── std::this_thread::yield()   : 暂时让出CPU时间片
```
#### thread函数的应用
- 创建线程
```c
template< class Function, class... Args >
explicit thread(Function&& f, Args&&... args);  // 创建线程，并传递参数给函数，可以是多个参数
```
对于这个函数注意命名空间，对于类内的参数，如果thread在类内定义，直接用this指针，如果在类外定义
```c
// 线程创建时传递成员函数和 this 指针
std::thread t(&FooBar::foo, this, 参数列表);

MyClass obj;
// 通过 std::thread 调用 MyClass 的成员函数
std::thread t(&MyClass::printMessage, &obj); // 传递成员函数指针和对象指针
```


- 移动 std::thread 对象

感觉和转接所有权差不多，t1 被移动给了 t2，因此 t1 不再关联线程，不能再调用 join() 或其他成员函数
```c
std::thread t1(myFunction);  // 创建线程
// 将 t1 移动给 t2
std::thread t2 = std::move(t1);
```
- 联接

在调用 join() 或 detach() 之前，最好检查线程是否可联接，避免程序崩溃
```c
// bool joinable() const;  // 检查线程是否可联接
#include <iostream>
#include <thread>

void myFunction() {
    std::cout << "Hello from thread!" << std::endl;
}

int main() {
    std::thread t;

    if (t.joinable()) {
        t.join();
    } else {
        std::cout << "Thread is not joinable." << std::endl;
    }

    t = std::thread(myFunction);  // 现在 t 关联到一个新的线程

    if (t.joinable()) {
        t.join();
    }

    return 0;
}
```
- 获取线程 ID：get_id()
```c
std::thread::id get_id() const;  // 获取线程的 ID
```
- 线程休眠

有时你希望让线程暂停执行一段时间，可以使用 sleep_for() 或 sleep_until()
```c
template< class Rep, class Period >
void std::this_thread::sleep_for(const std::chrono::duration<Rep, Period>& rel_time);  // 使当前线程休眠指定时间

template< class Clock, class Duration >
void std::this_thread::sleep_until(const std::chrono::time_point<Clock, Duration>& abs_time);  // 使当前线程休眠直到指定时间
```

-  线程间通信

线程间通信是多线程编程的重要部分。std::promise 和 std::future 提供了一种方便的方式让线程间传递数据。

其实异步更好一些，这部分到时候再展开

### 锁和条件变量
#### std::mutex：互斥锁
```c
class mutex {
    public:
        void lock();        // 阻塞，直到成功加锁
        void unlock();      // 解锁互斥锁
        bool try_lock();    // 尝试加锁，如果锁定成功返回 true，否则立即返回 false
};
```

#### std::lock_guard：自动管理互斥锁
```c
template< class Mutex >
class lock_guard {
public:
explicit lock_guard( Mutex& m );  // 构造时自动加锁
~lock_guard();                    // 析构时自动解锁
};
```
```c
std::mutex mtx;  // 全局互斥锁
int shared_data = 0;

void increment() {
    for (int i = 0; i < 10000; ++i) {
        std::lock_guard<std::mutex> lock(mtx);  // 自动加锁和解锁
        ++shared_data;
        // 当 lock 离开作用域时自动解锁
    }
}
```
std::lock_guard 会在构造时自动加锁，并在其生命周期结束时自动解锁，这简化了显式的 lock() 和 unlock() 操作，避免了手动管理锁的错误

#### std::unique_lock：灵活管理锁
std::unique_lock 提供了比 std::lock_guard 更加灵活的锁管理方式。它允许手动加锁和解锁，甚至可以延迟加锁、提前解锁，适合需要更复杂的锁控制的场景
```c
template< class Mutex >
class unique_lock {
    public:
        explicit unique_lock( Mutex& m );         // 构造时加锁
        unique_lock( Mutex& m, std::defer_lock ); // 创建锁对象但不立即加锁，允许手动控制锁的时机
        unique_lock( Mutex& m, std::try_to_lock );// 可以立即尝试加锁，而不是阻塞等待
        unique_lock( Mutex& m, std::adopt_lock ); // 锁已加锁状态
        void lock();                              // 手动加锁
        void unlock();                            // 手动解锁
        bool owns_lock() const;                   // 返回当前是否拥有锁
        Mutex* release();                         // 释放锁的控制权，但不解锁
};
```
```c
void task(int id) {
    std::cout << "Thread " << id << " is trying to lock...\n";
    
    // std::unique_lock 默认会阻塞线程直到获得锁
    std::unique_lock<std::mutex> lock(mtx);

    std::cout << "Thread " << id << " has locked and is incrementing shared_data.\n";
    ++shared_data;
    std::cout << "Thread " << id << " incremented shared_data to " << shared_data << "\n";
    
    // 自动解锁在 lock 对象的作用域结束时
}
```
```c
void task(int id) {
    std::unique_lock<std::mutex> lock(mtx, std::defer_lock);  // 延迟加锁
    
    std::cout << "Thread " << id << " is trying to lock...\n";
    lock.lock();  // 手动加锁，这里会阻塞线程直到获得锁

    std::cout << "Thread " << id << " has locked and is incrementing shared_data.\n";
    ++shared_data;
    std::cout << "Thread " << id << " incremented shared_data to " << shared_data << "\n";

    lock.unlock();  // 手动解锁，允许其他线程获得锁
}
```
- std::try_to_lock：尝试加锁（非阻塞）
  - 用于尝试获取互斥锁，但不会阻塞当前线程。如果锁已经被其他线程持有，std::try_to_lock 会立即返回，而不会等待锁被释放
- std::adopt_lock：接受一个已加锁的互斥锁
  - 用于接管已经由其他机制加锁的互斥锁，而不会尝试再加锁。也就是说，锁已经被加锁，当前线程只是声明它现在要管理这个锁
  - 当你通过某种方式已经手动加锁（例如通过 mtx.lock()），然后需要通过 std::unique_lock 管理这个锁的生命周期时，可以使用 std::adopt_lock
```c
#include <iostream>
#include <thread>
#include <mutex>

std::mutex mtx;

void adopt_lock_task() {
    mtx.lock();  // 手动加锁
    std::cout << "Mutex manually locked.\n";

    std::unique_lock<std::mutex> lock(mtx, std::adopt_lock);  // 接管已加锁的锁

    std::cout << "Managed by unique_lock, performing critical work.\n";
    // 锁将在 lock 离开作用域时自动释放
}

int main() {
    std::thread t(adopt_lock_task);

    t.join();

    return 0;
}
```

#### unique_lock和lock_guard的使用
std::unique_lock 和 lock_guard 对象的设计是为了在单个线程中管理锁，而不能在多个线程之间共享同一个 std::unique_lock 对象，它们俩主要作用是
- 在单个线程中锁定互斥锁（如 std::mutex）并管理锁的生命周期
- 通过 RAII（Resource Acquisition Is Initialization）原则自动在作用域结束时释放锁

  它本质上是一个线程内的工具，保证当前线程在持有锁时能够安全地操作共享资源，并在不需要锁时及时释放锁

#### std::condition_variable：条件变量
```c
class condition_variable {
    public:
        void wait( std::unique_lock<std::mutex>& lock );          // 等待条件满足，释放锁并进入阻塞状态
        template< class Predicate >
        void wait( std::unique_lock<std::mutex>& lock, Predicate pred ); // 带条件的等待，直到 pred 返回 true
        void notify_one();          // 通知一个等待的线程
        void notify_all();          // 通知所有等待的线程
};
```
cv.wait(lock, predicate);：带有谓词的 wait() 函数会在唤醒时首先检查谓词。
如果谓词为 true，则不进入等待状态；如果谓词为 false，则会释放锁并进入等待状态，直到条件满足并再次唤醒
```c
cv.wait(lock, [] { return ready; });
```
```c
#include <iostream>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>

std::mutex mtx;
std::condition_variable cv;
std::queue<int> buffer;
const unsigned int max_buffer_size = 10;

void producer() {
    int value = 0;
    while (value < 50) {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait(lock, [] { return buffer.size() < max_buffer_size; });  // 等待缓冲区有空间
        buffer.push(value++);
        std::cout << "Produced: " << value << std::endl;
        cv.notify_all();  // 通知消费者
    }
}

void consumer() {
    while (true) {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait(lock, [] { return !buffer.empty(); });  // 等待缓冲区有数据
        int value = buffer.front();
        buffer.pop();
        std::cout << "Consumed: " << value << std::endl;
        cv.notify_all();  // 通知生产者
        if (value == 49) break;  // 消费到50结束
    }
}

int main() {
    std::thread prod(producer);
    std::thread cons(consumer);

    prod.join();
    cons.join();

    return 0;
}
```

### optional
std::optional 是 C++17 引入的一种数据类型，用于表示一个值可以存在也可以不存在。
它与 Rust 的 Option 类型类似，允许你安全地处理那些可能没有值的情况，避免了直接使用指针带来的空指针（null）错误。
```c
std::optional<T>
├── 数据成员（内部实现）
│   ├── std::aligned_storage<sizeof(T), alignof(T)>::type storage
│   │   └── 用于存储类型为 T 的对象（未初始化的内存）
│   ├── bool has_value_flag
│       └── 用于标记 optional 是否存储了有效的值
│
├── 构造函数
│   ├── optional() noexcept
│   │   └── 默认构造函数，创建无值状态的 optional
│   ├── optional(const T& value)
│   │   └── 通过传入值构造，创建有值状态的 optional
│   ├── optional(T&& value)
│   │   └── 移动构造，创建有值状态的 optional
│   ├── optional(const optional& other)
│   │   └── 复制构造，创建一个新的 optional 并复制 other 的值（如果有）
│   ├── optional(optional&& other)
│       └── 移动构造，从其他 optional 移动其内容
│
├── 赋值运算符
│   ├── optional& operator=(const T& value)
│   │   └── 复制赋值，将 T 类型的值赋给 optional
│   ├── optional& operator=(T&& value)
│   │   └── 移动赋值，将 T 类型的值移动给 optional
│   ├── optional& operator=(const optional& other)
│   │   └── 复制赋值，将 other 赋值给当前 optional
│   ├── optional& operator=(optional&& other)
│       └── 移动赋值，将 other 的值移动到当前 optional
│
├── 析构函数
│   └── ~optional()
│       └── 析构函数，销毁 optional 中的值（如果有），并重置为无值状态
│
├── 成员函数
│   ├── bool has_value() const noexcept
│   │   └── 检查 optional 是否包含有效值，返回 true 表示有值
│   ├── T& value()
│   │   └── 返回存储的值，如果没有值则抛出 std::bad_optional_access 异常
│   ├── const T& value() const
│   │   └── const 版本的 value 函数，返回存储的值，若无值则抛异常
│   ├── T value_or(const T& default_value) const
│   │   └── 如果有值，返回存储的值；如果无值，返回 default_value
│   ├── void reset() noexcept
│   │   └── 将 optional 置为无值状态，如果有值则调用析构函数释放资源
│   ├── template <typename... Args>
│   │    T& emplace(Args&&... args)
│   │    └── 构造一个新的 T 对象并存储到 optional 中，替换现有的值
│
├── 其他运算符
│   ├── T& operator*()
│   │   └── 解引用运算符，返回存储的值
│   ├── const T& operator*() const
│   │   └── const 版本的解引用运算符，返回存储的值
│   ├── T* operator->()
│   │   └── 指针访问运算符，返回存储的值的指针
│   ├── const T* operator->() const
│   │   └── const 版本的指针访问运算符，返回存储值的指针
│
└── 异常
    └── std::bad_optional_access
        └── 当尝试访问无值的 optional 时抛出的异常
```




### barrier
c++20引入了std::barrier

```shell
std::barrier (C++20)
├── 构造函数
│   ├── std::barrier(ptrdiff_t expected):  创建一个屏障，设定线程数
│   └── std::barrier(ptrdiff_t expected, CompletionFunction callback):
│       └── 创建一个屏障，设置线程数并定义回调函数，当所有线程到达屏障后，执行回调
│
├── 常用成员函数
│   ├── arrive()              : 表示当前线程到达屏障，但不等待其他线程
│   │   └── 返回剩余等待线程数
│   ├── arrive_and_wait()     : 当前线程到达屏障并等待其他线程，所有线程到达后继续执行
│   ├── arrive_and_drop()     : 当前线程到达屏障并退出屏障，不再参与接下来的同步
│   ├── reset()               : 重置屏障，使其可重新使用
│   └── expected()            : 返回当前屏障期望的线程数量
│
├── 回调函数 (可选)
│   └── 在所有线程到达屏障时执行，可以用于执行某些状态更新或其他操作
│
├── 内部同步机制
│   ├── 自动重置：每当所有线程到达屏障时，屏障会自动重置，准备下一次同步
│   └── 并发安全：屏障的所有操作是线程安全的
│
└── 屏障使用场景
    ├── 多阶段任务的同步
    ├── 在多个线程的并行操作完成某个步骤后，统一等待进入下一个步骤
    └── 通过回调函数控制共享资源或执行特定任务
```


#### lambda表达式
lambda表达式在回调函数这边很常用，这里补充一下

Lambda 表达式是一种可以在代码中简洁地定义内联函数的语法，特别适合临时性、一次性使用的函数，常用于回调、算法或多线程等场景
```c
[捕获列表] (参数列表) -> 返回类型 {
    函数体
}
```
- 捕获列表（[]）：用于指定从外部作用域中捕获哪些变量
- 参数列表（()）：可以为空或者包含一个或多个参数
- 返回类型（->）：（可选）用于指定返回类型，如果省略，编译器会根据函数体自动推断
- 函数体（{}）：就是 Lambda 表达式的具体实现部分，类似普通函数的实现

对于参数列表，是可以模拟函数
```c
[](int x) { cout << static_cast<char>(x + 48); 
```

捕获列表算是核心的部分
- []：不捕获任何外部变量
- [=]：按值捕获外部变量，Lambda 内部可以使用外部变量的拷贝
- [&]：按引用捕获外部变量，Lambda 内部可以修改外部变量
- [this]：捕获当前类的this指针，允许 Lambda 访问类的成员
- [a, &b]：按值捕获 a，按引用捕获 b，捕获列表中可以混合按值和按引用

关于捕获列表，注意的一点是Lambda 捕获列表是显式的，它需要你在 [] 中明确指定捕获的外部变量（按值或按引用）。
这些捕获的变量存在于 Lambda 定义时的作用域 中，通常并不需要作为 Lambda 的参数传入。

```c
#include <iostream>

class Button {
public:
    void onClick() {
        // 捕获 this，访问类的成员函数和成员变量
        auto handleClick = [this]() {
            std::cout << "Button clicked! Updating status." << std::endl;
            this->status = "Clicked";  // 修改类的成员变量
        };

        // 模拟按钮点击事件
        handleClick();
    }

    void printStatus() {
        std::cout << "Button status: " << status << std::endl;
    }

private:
    std::string status = "Not clicked";
};

int main() {
    Button button;
    button.printStatus();

    // 模拟点击按钮
    button.onClick();
    button.printStatus();

    return 0;
}
```

```c
#include <iostream>
#include <thread>

int main() {
    int fixed_data = 100;
    int state = 0;

    // 按值捕获 fixed_data，按引用捕获 state
    auto task = [fixed_data, &state]() {
        state = fixed_data * 2;  // 修改 state，但不能修改 fixed_data
        std::cout << "Task completed. State updated to: " << state << std::endl;
    };

    // 创建并运行线程
    std::thread t(task);
    t.join();  // 等待子线程执行完毕

    // 输出修改后的状态
    std::cout << "Final state: " << state << std::endl;

    return 0;
}
```

#### barrier函数的应用
```c++
std::barrier<decltype(auto)> barrier(线程数量, 可选的回调函数);
```
- 线程数量：指要等待的线程的数量。当这么多线程都到达屏障点时，所有线程才会继续执行
- 可选的回调函数（可省略）：当所有线程都到达屏障点时，会执行该回调函数。回调函数可以用来执行某些操作，比如改变状态、更新共享数据等





### 例题
- 交替输出奇偶数字升级版
![img_7.png](img_7.png)
```c
class ZeroEvenOdd {
private:
    int n;
    condition_variable cv;
    int now;
    bool flag;
    mutex mx;

public:
    ZeroEvenOdd(int n) {
        this->n = n;
        now = 0;
        flag = false;
        thread tz(&ZeroEvenOdd::zero, this, [](int x) { cout << x; });
        thread te(&ZeroEvenOdd::even, this, [](int x) { cout << x; });
        
        if(n > 1) {
            thread to(&ZeroEvenOdd::odd, this, [](int x) { cout << x; });
            to.join();
        }
        tz.join();
        te.join();
    }

    // printNumber(x) outputs "x", where x is an integer.
    void zero(function<void(int)> printNumber) {
        while(now < n){
            unique_lock lg(mx);
            printNumber(0);
            flag = true;
            cv.notify_all();
            while(flag){
                cv.wait(lg);
            }
        }
    }

    void even(function<void(int)> printNumber) {
        while(now < n){
            unique_lock lg(mx);
            while(now % 2 == 1 || !flag){ // 由于多线程的情况，当now >=n时候，相当于外循环已经不满足了，但仍困在内循环
                cv.wait(lg);
            }
            printNumber(now);
            flag = false;
            now++;
            cv.notify_all();
        }
    }

    void odd(function<void(int)> printNumber) {
        while(now < n){
            unique_lock lg(mx);
            while(now % 2 == 0 || !flag){// 这里同理
                cv.wait(lg);
            }
            printNumber(now);
            flag = false;
            now++;
            cv.notify_all();
        }
    }
};
```
- 对于上面的情况，能总结的
  - 对于多线程问题，首先确定哪些数据是要共享的
  - 对于共享数据
    - 共享数据的访问控制，互斥锁保护等是一方面
    - 另外一方面就是互斥数据的更新，以及更新可能导致的影响（上面就是内部循环时候，对更新带来的影响没有考虑全面）
  - 要尽可能控制共享数据的影响范围，共享数据更新有时候不是所有情况都能想到
    - 共享的数据尽量少点，能线程独有就独有，少犯错
  - 对于线程中的标志，尽可能一个线程一个，当不得不共享时候，要么就别用它来区分单个，单独建立个东西来区分







