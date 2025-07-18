//
// Created by karthi on 18/07/25.
//

#include "TaskQueue.h"

void TaskQueue::push(Task task) {
     std::unique_lock<std::mutex> lock(mutex);
     tasks.push(move(task));
     condition.notify_one();
}

Task TaskQueue::pop() {
     unique_lock<std::mutex> lock(mutex);
     condition.wait(lock, [this]() { return !tasks.empty(); });
     Task task = move(tasks.front());
     tasks.pop();
     return task;
}

