import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { taskApi, TaskConfig } from '@/api/tasks'
import { assetApi } from '@/api/assets'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Badge } from '@/components/ui/badge'
import { useToast } from '@/components/ui/use-toast'
import { Play, Plus, X } from 'lucide-react'
import { cn } from '@/lib/utils'

const scanTypes = [
  { id: 'port_scan', label: '端口扫描', description: '扫描开放端口' },
  { id: 'service_detect', label: '服务识别', description: '识别服务类型和版本' },
  { id: 'vuln_scan', label: '漏洞扫描', description: '检测已知漏洞' },
  { id: 'fingerprint', label: '指纹识别', description: '识别目标指纹' },
  { id: 'subdomain', label: '子域名枚举', description: '发现子域名' },
  { id: 'takeover', label: '子域名接管', description: '检测子域名接管漏洞' },
  { id: 'crawler', label: 'Web爬虫', description: '爬取网站URL和接口' },
  { id: 'dir_scan', label: '目录扫描', description: '扫描敏感目录' },
]

// 检测目标类型
function detectTargetType(target: string): string {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(target)) return 'ip'
  if (/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(target)) return 'cidr'
  if (/^https?:\/\//.test(target)) return 'url'
  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(target)) return 'domain'
  return 'unknown'
}

interface TaskCreateDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export default function TaskCreateDialog({ open, onOpenChange }: TaskCreateDialogProps) {
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const [formData, setFormData] = useState({
    name: '',
    description: '',
    assetIds: [] as string[],
    config: {
      scanTypes: ['port_scan'],
      port_scan_mode: 'quick',
      portRange: '1-65535',
      rateLimit: 1000,
      timeout: 30,
      concurrent: 10,
    } as TaskConfig,
  })

  // 直接输入的目标
  const [directTargets, setDirectTargets] = useState<string[]>([])
  const [targetInput, setTargetInput] = useState('')
  const [targetMode, setTargetMode] = useState<'direct' | 'asset'>('direct')

  // 获取资产列表
  const { data: assetsData, isLoading: assetsLoading } = useQuery({
    queryKey: ['assets-for-task'],
    queryFn: () => assetApi.getAssets({ pageSize: 100 }),
    enabled: open,
  })

  // 创建任务
  const createMutation = useMutation({
    mutationFn: taskApi.createTask,
    onSuccess: () => {
      toast({ title: '任务创建成功' })
      queryClient.invalidateQueries({ queryKey: ['tasks'] })
      onOpenChange(false)
      resetForm()
    },
    onError: (error: Error) => {
      toast({ title: '创建失败', description: error.message, variant: 'destructive' })
    },
  })

  const assets = assetsData?.data?.list || []

  const resetForm = () => {
    setFormData({
      name: '',
      description: '',
      assetIds: [],
      config: {
        scanTypes: ['port_scan'],
        port_scan_mode: 'quick',
        portRange: '1-65535',
        rateLimit: 1000,
        timeout: 30,
        concurrent: 10,
      },
    })
    setDirectTargets([])
    setTargetInput('')
    setTargetMode('direct')
  }

  // 添加直接输入的目标
  const addDirectTargets = () => {
    if (!targetInput.trim()) return
    const newTargets = targetInput
      .split(/[\n,\s]+/)
      .map(t => t.trim())
      .filter(t => t.length > 0)
    const uniqueTargets = [...new Set([...directTargets, ...newTargets])]
    setDirectTargets(uniqueTargets)
    setTargetInput('')
  }

  const removeDirectTarget = (target: string) => {
    setDirectTargets(directTargets.filter(t => t !== target))
  }

  const clearDirectTargets = () => {
    setDirectTargets([])
  }

  // 根据选择的扫描类型自动确定任务类型
  const getTaskType = (scanTypes: string[]): string => {
    if (scanTypes.length === 0) return 'port_scan'
    if (scanTypes.length === 1) {
      // 单一扫描类型直接返回对应类型
      return scanTypes[0]
    }
    // 多种扫描类型使用 full 模式，让后端流水线处理
    return 'full'
  }

  const handleSubmit = (_startImmediately = false) => {
    if (!formData.name.trim()) {
      toast({ title: '请输入任务名称', variant: 'destructive' })
      return
    }
    
    // 根据输入模式验证目标
    let targets: string[] = []
    let targetType: string = 'unknown'

    if (targetMode === 'direct') {
      // 如果输入框有内容，自动添加到目标列表
      let finalTargets = [...directTargets]
      if (targetInput.trim()) {
        const newTargets = targetInput
          .split(/[\n,\s]+/)
          .map(t => t.trim())
          .filter(t => t.length > 0)
        finalTargets = [...new Set([...finalTargets, ...newTargets])]
      }
      
      if (finalTargets.length === 0) {
        toast({ title: '请输入至少一个扫描目标', variant: 'destructive' })
        return
      }
      targets = finalTargets
      const types = [...new Set(targets.map(detectTargetType))]
      targetType = types.length === 1 ? types[0] : 'mixed'
    } else {
      if (formData.assetIds.length === 0) {
        toast({ title: '请选择至少一个资产', variant: 'destructive' })
        return
      }
      const selectedAssets = assets.filter(a => formData.assetIds.includes(a.id))
      targets = selectedAssets.map(a => a.target)
      const types = [...new Set(selectedAssets.map(a => a.type))]
      targetType = types.length === 1 ? types[0] : 'mixed'
    }

    if ((formData.config.scanTypes?.length ?? 0) === 0) {
      toast({ title: '请选择至少一种扫描类型', variant: 'destructive' })
      return
    }

    // 转换配置字段为后端格式 (snake_case)
    const configForBackend = {
      ...formData.config,
      scan_types: formData.config.scanTypes, // 后端使用 snake_case
    }

    // 根据选择的扫描类型自动确定任务类型
    const taskType = getTaskType(formData.config.scanTypes || [])

    createMutation.mutate({
      name: formData.name,
      type: taskType,
      targets: targets,
      targetType: targetType,
      description: formData.description,
      config: configForBackend,
    })
  }

  const toggleScanType = (scanTypeId: string) => {
    const current = formData.config.scanTypes || []
    if (current.includes(scanTypeId)) {
      setFormData({
        ...formData,
        config: {
          ...formData.config,
          scanTypes: current.filter((t) => t !== scanTypeId),
        },
      })
    } else {
      setFormData({
        ...formData,
        config: {
          ...formData.config,
          scanTypes: [...current, scanTypeId],
        },
      })
    }
  }

  const toggleAsset = (assetId: string) => {
    if (formData.assetIds.includes(assetId)) {
      setFormData({
        ...formData,
        assetIds: formData.assetIds.filter((id) => id !== assetId),
      })
    } else {
      setFormData({
        ...formData,
        assetIds: [...formData.assetIds, assetId],
      })
    }
  }

  const selectAllAssets = () => {
    if (formData.assetIds.length === assets.length) {
      setFormData({ ...formData, assetIds: [] })
    } else {
      setFormData({ ...formData, assetIds: assets.map((a) => a.id) })
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-3xl max-h-[90vh] overflow-hidden flex flex-col p-0">
        <DialogHeader className="px-6 pt-6 pb-4 border-b">
          <DialogTitle className="text-lg font-semibold">创建扫描任务</DialogTitle>
        </DialogHeader>

        {/* 内容区域 */}
        <div className="flex-1 overflow-auto px-6 py-5 space-y-5">
          {/* 任务信息 */}
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label className="text-sm">任务名称 <span className="text-destructive">*</span></Label>
              <Input
                placeholder="例如：每日安全扫描"
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              />
            </div>
            <div className="space-y-2">
              <Label className="text-sm">任务描述</Label>
              <Input
                placeholder="可选"
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              />
            </div>
          </div>

          {/* 扫描目标 */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <Label className="text-sm">扫描目标 <span className="text-destructive">*</span></Label>
              <Tabs value={targetMode} onValueChange={(v) => setTargetMode(v as 'direct' | 'asset')} className="h-8">
                <TabsList className="h-8 p-1">
                  <TabsTrigger value="direct" className="text-xs h-6 px-3">直接输入</TabsTrigger>
                  <TabsTrigger value="asset" className="text-xs h-6 px-3">从资产选择</TabsTrigger>
                </TabsList>
              </Tabs>
            </div>
            
            {targetMode === 'direct' ? (
              <div className="border rounded-lg p-4 bg-muted/30">
                <div className="flex gap-4">
                  <div className="flex-1">
                    <Textarea
                      placeholder="输入目标，每行一个或用逗号分隔&#10;支持：IP / 域名 / URL / CIDR&#10;&#10;示例：&#10;192.168.1.1&#10;example.com&#10;https://target.com"
                      value={targetInput}
                      onChange={(e) => setTargetInput(e.target.value)}
                      className="min-h-[120px] bg-background resize-none font-mono text-sm"
                    />
                    <Button type="button" onClick={addDirectTargets} size="sm" className="mt-2">
                      <Plus className="h-4 w-4 mr-1" />
                      添加到列表
                    </Button>
                  </div>
                  <div className="w-64">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm text-muted-foreground">目标列表</span>
                      {directTargets.length > 0 && (
                        <Button variant="ghost" size="sm" className="h-6 text-xs" onClick={clearDirectTargets}>
                          清空
                        </Button>
                      )}
                    </div>
                    <div className="border rounded-lg bg-background min-h-[120px] max-h-[120px] overflow-auto">
                      {directTargets.length === 0 ? (
                        <div className="flex items-center justify-center h-[120px] text-sm text-muted-foreground">
                          暂无目标
                        </div>
                      ) : (
                        <div className="p-2 space-y-1">
                          {directTargets.map((target, index) => (
                            <div
                              key={index}
                              className="flex items-center gap-2 px-2 py-1 rounded hover:bg-muted group"
                            >
                              <Badge variant="secondary" className="text-[10px] font-normal shrink-0">
                                {detectTargetType(target)}
                              </Badge>
                              <span className="flex-1 truncate text-xs font-mono">{target}</span>
                              <X
                                className="h-3 w-3 text-muted-foreground cursor-pointer opacity-0 group-hover:opacity-100 shrink-0"
                                onClick={() => removeDirectTarget(target)}
                              />
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                    <div className="mt-2 text-xs text-muted-foreground text-center">
                      共 {directTargets.length} 个目标
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="border rounded-lg p-4 bg-muted/30">
                <div className="flex items-center justify-between mb-3">
                  <span className="text-sm text-muted-foreground">
                    已选择 <span className="font-medium text-foreground">{formData.assetIds.length}</span> 个资产
                  </span>
                  <Button variant="ghost" size="sm" className="h-7" onClick={selectAllAssets}>
                    {formData.assetIds.length === assets.length ? '取消全选' : '全选'}
                  </Button>
                </div>
                <div className="border rounded-lg bg-background max-h-[140px] overflow-auto">
                  {assetsLoading ? (
                    <div className="flex items-center justify-center h-[100px] text-sm text-muted-foreground">
                      加载中...
                    </div>
                  ) : assets.length === 0 ? (
                    <div className="flex items-center justify-center h-[100px] text-sm text-muted-foreground">
                      暂无资产，请先添加或切换到直接输入
                    </div>
                  ) : (
                    <div className="grid grid-cols-2 gap-px bg-border">
                      {assets.map((asset) => (
                        <div
                          key={asset.id}
                          className={cn(
                            'p-3 cursor-pointer transition-colors bg-background',
                            formData.assetIds.includes(asset.id)
                              ? 'bg-primary/5'
                              : 'hover:bg-muted/50'
                          )}
                          onClick={() => toggleAsset(asset.id)}
                        >
                          <div className="flex items-center gap-2">
                            <Checkbox checked={formData.assetIds.includes(asset.id)} className="shrink-0" />
                            <div className="flex-1 min-w-0">
                              <div className="text-sm font-medium truncate">{asset.name}</div>
                              <div className="text-xs text-muted-foreground truncate">{asset.target}</div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* 扫描类型 */}
          <div className="space-y-3">
            <Label className="text-sm">扫描类型 <span className="text-destructive">*</span></Label>
            <div className="grid grid-cols-4 gap-2">
              {scanTypes.map((type) => (
                <div
                  key={type.id}
                  className={cn(
                    'relative p-3 border rounded-lg cursor-pointer transition-all text-center',
                    formData.config.scanTypes?.includes(type.id)
                      ? 'border-primary bg-primary/5 shadow-sm'
                      : 'hover:bg-muted/50 hover:border-muted-foreground/20'
                  )}
                  onClick={() => toggleScanType(type.id)}
                >
                  {formData.config.scanTypes?.includes(type.id) && (
                    <div className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-primary" />
                  )}
                  <div className="font-medium text-sm">{type.label}</div>
                  <div className="text-[11px] text-muted-foreground mt-0.5">{type.description}</div>
                </div>
              ))}
            </div>
          </div>

          {/* 高级配置 - 折叠 */}
          <div className="space-y-3">
            <Label className="text-sm">扫描参数</Label>
            <div className="grid grid-cols-4 gap-3 p-4 border rounded-lg bg-muted/30">
              <div className="space-y-1.5">
                <Label className="text-xs text-muted-foreground">端口模式</Label>
                <Select
                  value={formData.config.port_scan_mode || 'quick'}
                  onValueChange={(value) =>
                    setFormData({
                      ...formData,
                      config: { ...formData.config, port_scan_mode: value },
                    })
                  }
                >
                  <SelectTrigger className="h-8 text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="quick">快速扫描</SelectItem>
                    <SelectItem value="top1000">Top 1000</SelectItem>
                    <SelectItem value="full">全端口</SelectItem>
                    <SelectItem value="custom">自定义</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs text-muted-foreground">速率限制</Label>
                <Input
                  type="number"
                  className="h-8 text-xs"
                  value={formData.config.rateLimit || ''}
                  onChange={(e) =>
                    setFormData({
                      ...formData,
                      config: { ...formData.config, rateLimit: Number(e.target.value) },
                    })
                  }
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs text-muted-foreground">超时 (秒)</Label>
                <Input
                  type="number"
                  className="h-8 text-xs"
                  value={formData.config.timeout || ''}
                  onChange={(e) =>
                    setFormData({
                      ...formData,
                      config: { ...formData.config, timeout: Number(e.target.value) },
                    })
                  }
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs text-muted-foreground">并发数</Label>
                <Input
                  type="number"
                  className="h-8 text-xs"
                  value={formData.config.concurrent || ''}
                  onChange={(e) =>
                    setFormData({
                      ...formData,
                      config: { ...formData.config, concurrent: Number(e.target.value) },
                    })
                  }
                />
              </div>
              {formData.config.port_scan_mode === 'custom' && (
                <div className="col-span-4 space-y-1.5">
                  <Label className="text-xs text-muted-foreground">自定义端口</Label>
                  <Input
                    className="h-8 text-xs"
                    placeholder="例如: 80,443,8080-8090"
                    value={formData.config.portRange || ''}
                    onChange={(e) =>
                      setFormData({
                        ...formData,
                        config: { ...formData.config, portRange: e.target.value },
                      })
                    }
                  />
                </div>
              )}
            </div>
          </div>
        </div>

        {/* 底部操作按钮 */}
        <div className="flex justify-end gap-2 px-6 py-4 border-t bg-muted/30">
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            取消
          </Button>
          <Button onClick={() => handleSubmit(true)} disabled={createMutation.isPending}>
            <Play className="h-4 w-4 mr-1.5" />
            创建任务
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}
