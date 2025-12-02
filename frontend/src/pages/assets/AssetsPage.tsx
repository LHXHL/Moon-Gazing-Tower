import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { assetApi, Asset } from '@/api/assets'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Label } from '@/components/ui/label'
import { useToast } from '@/components/ui/use-toast'
import { cn, formatDate, getStatusColor } from '@/lib/utils'
import {
  Plus,
  Search,
  Trash2,
  Eye,
  Upload,
  Download,
  RefreshCw,
  Server,
  Globe,
  Monitor,
  Smartphone,
} from 'lucide-react'
import { Link } from 'react-router-dom'

const assetTypeIcons = {
  ip: Server,
  domain: Globe,
  web: Monitor,
  app: Smartphone,
}

const assetTypeLabels = {
  ip: 'IP地址',
  domain: '域名',
  web: 'Web应用',
  app: 'APP',
}

export default function AssetsPage() {
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState<string>('all')
  const [page, setPage] = useState(1)
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false)
  const [newAsset, setNewAsset] = useState({
    name: '',
    type: 'ip' as Asset['type'],
    target: '',
    tags: '',
  })

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['assets', page, search, typeFilter],
    queryFn: () =>
      assetApi.getAssets({
        page,
        pageSize: 10,
        search,
        type: typeFilter === 'all' ? undefined : typeFilter,
      }),
  })

  const createMutation = useMutation({
    mutationFn: assetApi.createAsset,
    onSuccess: () => {
      toast({ title: '创建成功', description: '资产已添加' })
      setIsCreateDialogOpen(false)
      setNewAsset({ name: '', type: 'ip', target: '', tags: '' })
      queryClient.invalidateQueries({ queryKey: ['assets'] })
    },
    onError: () => {
      toast({ title: '创建失败', description: '请稍后重试', variant: 'destructive' })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: assetApi.deleteAsset,
    onSuccess: () => {
      toast({ title: '删除成功' })
      queryClient.invalidateQueries({ queryKey: ['assets'] })
    },
    onError: () => {
      toast({ title: '删除失败', description: '请稍后重试', variant: 'destructive' })
    },
  })

  const handleCreate = () => {
    if (!newAsset.name || !newAsset.target) {
      toast({ title: '请填写完整', description: '名称和目标不能为空', variant: 'destructive' })
      return
    }
    createMutation.mutate({
      name: newAsset.name,
      type: newAsset.type,
      target: newAsset.target,
      tags: newAsset.tags ? newAsset.tags.split(',').map((t) => t.trim()) : [],
    })
  }

  const assets = data?.data?.list || []
  const total = data?.data?.total || 0
  const totalPages = Math.ceil(total / 10)

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-2xl font-bold">资产管理</h1>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            刷新
          </Button>
          <Button variant="outline" size="sm">
            <Upload className="h-4 w-4 mr-2" />
            导入
          </Button>
          <Button variant="outline" size="sm">
            <Download className="h-4 w-4 mr-2" />
            导出
          </Button>
          <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
            <DialogTrigger asChild>
              <Button size="sm">
                <Plus className="h-4 w-4 mr-2" />
                添加资产
              </Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>添加资产</DialogTitle>
                <DialogDescription>添加一个新的扫描目标资产</DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label>名称</Label>
                  <Input
                    value={newAsset.name}
                    onChange={(e) => setNewAsset({ ...newAsset, name: e.target.value })}
                    placeholder="资产名称"
                  />
                </div>
                <div className="space-y-2">
                  <Label>类型</Label>
                  <Select
                    value={newAsset.type}
                    onValueChange={(v) => setNewAsset({ ...newAsset, type: v as Asset['type'] })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="ip">IP地址</SelectItem>
                      <SelectItem value="domain">域名</SelectItem>
                      <SelectItem value="web">Web应用</SelectItem>
                      <SelectItem value="app">APP</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>目标</Label>
                  <Input
                    value={newAsset.target}
                    onChange={(e) => setNewAsset({ ...newAsset, target: e.target.value })}
                    placeholder="IP地址、域名或URL"
                  />
                </div>
                <div className="space-y-2">
                  <Label>标签（逗号分隔）</Label>
                  <Input
                    value={newAsset.tags}
                    onChange={(e) => setNewAsset({ ...newAsset, tags: e.target.value })}
                    placeholder="tag1, tag2, tag3"
                  />
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setIsCreateDialogOpen(false)}>
                  取消
                </Button>
                <Button onClick={handleCreate} disabled={createMutation.isPending}>
                  创建
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      {/* Filters */}
      <div className="flex gap-4">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="搜索资产..."
            className="pl-9"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <Select value={typeFilter} onValueChange={setTypeFilter}>
          <SelectTrigger className="w-40">
            <SelectValue placeholder="选择类型" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部类型</SelectItem>
            <SelectItem value="ip">IP地址</SelectItem>
            <SelectItem value="domain">域名</SelectItem>
            <SelectItem value="web">Web应用</SelectItem>
            <SelectItem value="app">APP</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Table */}
      <div className="border rounded-lg">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>名称</TableHead>
              <TableHead>类型</TableHead>
              <TableHead>目标</TableHead>
              <TableHead>状态</TableHead>
              <TableHead>标签</TableHead>
              <TableHead>上次扫描</TableHead>
              <TableHead>操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading ? (
              <TableRow>
                <TableCell colSpan={7} className="text-center py-8">
                  加载中...
                </TableCell>
              </TableRow>
            ) : assets.length === 0 ? (
              <TableRow>
                <TableCell colSpan={7} className="text-center py-8 text-muted-foreground">
                  暂无数据
                </TableCell>
              </TableRow>
            ) : (
              assets.map((asset) => {
                const TypeIcon = assetTypeIcons[asset.type]
                return (
                  <TableRow key={asset.id}>
                    <TableCell className="font-medium">
                      <div className="flex items-center gap-2">
                        <TypeIcon className="h-4 w-4 text-muted-foreground" />
                        {asset.name}
                      </div>
                    </TableCell>
                    <TableCell>{assetTypeLabels[asset.type]}</TableCell>
                    <TableCell className="font-mono text-sm">{asset.target}</TableCell>
                    <TableCell>
                      <Badge className={cn(getStatusColor(asset.status))}>{asset.status}</Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-1 flex-wrap">
                        {asset.tags?.slice(0, 3).map((tag) => (
                          <Badge key={tag} variant="outline" className="text-xs">
                            {tag}
                          </Badge>
                        ))}
                        {(asset.tags?.length || 0) > 3 && (
                          <Badge variant="outline" className="text-xs">
                            +{asset.tags!.length - 3}
                          </Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      {asset.lastScanTime ? formatDate(asset.lastScanTime) : '-'}
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-2">
                        <Button variant="ghost" size="icon" asChild>
                          <Link to={`/assets/${asset.id}`}>
                            <Eye className="h-4 w-4" />
                          </Link>
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => deleteMutation.mutate(asset.id)}
                        >
                          <Trash2 className="h-4 w-4 text-destructive" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                )
              })
            )}
          </TableBody>
        </Table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex justify-center gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={page === 1}
            onClick={() => setPage(page - 1)}
          >
            上一页
          </Button>
          <span className="py-2 px-4 text-sm">
            {page} / {totalPages}
          </span>
          <Button
            variant="outline"
            size="sm"
            disabled={page === totalPages}
            onClick={() => setPage(page + 1)}
          >
            下一页
          </Button>
        </div>
      )}
    </div>
  )
}
