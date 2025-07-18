//
// Created by karthi on 18/07/25.
//

#ifndef TASKQUEUE_H
#define TASKQUEUE_H
#include "Task.h"
#include <queue>
#include <mutex>
#include <condition_variable>

class TaskQueue {
private:
    std::queue<Task> tasks;
    std::mutex mutex;
    std::condition_variable condition;


public:
    void push(Task task);
    Task pop();

};


#endif //TASKQUEUE_H