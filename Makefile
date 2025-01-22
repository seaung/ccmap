# 编译器设置
CC = gcc
CFLAGS = -Wall -Wextra -O2 -I./include
DEBUG_FLAGS = -g -DDEBUG

# 目录设置
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

# 源文件和目标文件
SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

# 可执行文件
TARGET = $(BIN_DIR)/ccmap

# 默认目标
all: prepare $(TARGET)

# 创建必要的目录
prepare:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR)

# 编译规则
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# 链接规则
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET)

# 调试版本
debug: CFLAGS += $(DEBUG_FLAGS)
debug: all

# 清理规则
clean:
	@rm -rf $(OBJ_DIR) $(BIN_DIR)

# 重新编译
rebuild: clean all

# 伪目标
.PHONY: all prepare debug clean rebuild