#ifndef THREAD_SAFE_QUEUE_H
#define THREAD_SAFE_QUEUE_H

#include <queue>
#include <mutex>
#include <condition_variable>

template <typename T>
class ThreadSafeQueue {
public:
    // Pushes an item onto the queue and wakes up one waiting consumer.
    void push(T item) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            queue_.push(std::move(item));
        }
        cv_.notify_one();
    }

    // Blocks until an item is available OR shutdown() has been called.
    // Returns false if the queue is empty AND shutdown -- meaning
    // "nothing more is coming, stop waiting."
    bool waitAndPop(T& out) {
        std::unique_lock<std::mutex> lock(mutex_);

        // Wait until EITHER the queue has something OR we've been shut down.
        // We use a lambda predicate so this correctly handles "spurious
        // wakeups" -- condition_variable can wake up even with no notify,
        // so we always re-check the actual condition before proceeding.
        cv_.wait(lock, [this] { return !queue_.empty() || shutdown_; });

        if (queue_.empty()) {
            return false; // we were woken because of shutdown, not new data
        }

        out = std::move(queue_.front());
        queue_.pop();
        return true;
    }

    // Signals all waiting consumers that no more items are coming.
    // Called once, after the producer (pcap reader) finishes.
    void shutdown() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            shutdown_ = true;
        }
        cv_.notify_all(); // wake ALL waiting workers, not just one
    }

private:
    std::queue<T> queue_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    bool shutdown_ = false;
};

#endif
