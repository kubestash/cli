package tree

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

type TreeNode struct {
	Name     string
	Children map[string]*TreeNode
}

func newTreeNode(name string) *TreeNode {
	return &TreeNode{
		Name:     name,
		Children: make(map[string]*TreeNode),
	}
}

func (node *TreeNode) add(parts []string) {
	if len(parts) == 0 {
		return
	}

	childName := parts[0]
	if len(parts) == 1 {
		childName = strings.TrimSuffix(childName, filepath.Ext(childName))
	}

	if _, exists := node.Children[childName]; !exists {
		node.Children[childName] = newTreeNode(childName)
	}
	node.Children[childName].add(parts[1:])
}

func (node *TreeNode) print(prefix string, isLast bool) {
	if node.Name != "" {
		connector := "├── "
		if isLast {
			connector = "└── "
		}
		fmt.Println(prefix + connector + node.Name)
		prefix += func() string {
			if isLast {
				return "    "
			}
			return "│   "
		}()
	}

	keys := make([]string, 0, len(node.Children))
	for k := range node.Children {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for i, k := range keys {
		node.Children[k].print(prefix, i == len(keys)-1)
	}
}

func TreeView(files []string) {
	root := newTreeNode("")

	for _, file := range files {
		parts := strings.Split(file, "/")
		root.add(parts)
	}

	keys := make([]string, 0, len(root.Children))
	for k := range root.Children {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for i, k := range keys {
		root.Children[k].print("", i == len(keys)-1)
	}
}
