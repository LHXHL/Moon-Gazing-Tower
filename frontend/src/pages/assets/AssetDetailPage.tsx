import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { assetApi } from '@/api/assets'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { cn, formatDate, getStatusColor } from '@/lib/utils'
import { ArrowLeft, Play, Server, Globe, Monitor, Smartphone } from 'lucide-react'

const assetTypeIcons = {
  ip: Server,
  domain: Globe,
  web: Monitor,
  app: Smartphone,
}

export default function AssetDetailPage() {
  const { id } = useParams<{ id: string }>()

  const { data, isLoading } = useQuery({
    queryKey: ['asset', id],
    queryFn: () => assetApi.getAsset(id!),
    enabled: !!id,
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    )
  }

  const asset = data?.data

  if (!asset) {
    return (
      <div className="text-center py-8">
        <p className="text-muted-foreground">资产不存在</p>
        <Button asChild className="mt-4">
          <Link to="/assets">返回列表</Link>
        </Button>
      </div>
    )
  }

  const TypeIcon = assetTypeIcons[asset.type]

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="icon" asChild>
          <Link to="/assets">
            <ArrowLeft className="h-5 w-5" />
          </Link>
        </Button>
        <div className="flex-1">
          <div className="flex items-center gap-2">
            <TypeIcon className="h-6 w-6" />
            <h1 className="text-2xl font-bold">{asset.name}</h1>
            <Badge className={cn(getStatusColor(asset.status))}>{asset.status}</Badge>
          </div>
          <p className="text-muted-foreground font-mono">{asset.target}</p>
        </div>
        <Button>
          <Play className="h-4 w-4 mr-2" />
          开始扫描
        </Button>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>基本信息</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-sm text-muted-foreground">类型</p>
                <p className="font-medium">{asset.type.toUpperCase()}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">目标</p>
                <p className="font-medium font-mono">{asset.target}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">创建时间</p>
                <p className="font-medium">{formatDate(asset.createdAt)}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">上次扫描</p>
                <p className="font-medium">
                  {asset.lastScanTime ? formatDate(asset.lastScanTime) : '-'}
                </p>
              </div>
            </div>
            {asset.tags && asset.tags.length > 0 && (
              <div>
                <p className="text-sm text-muted-foreground mb-2">标签</p>
                <div className="flex gap-2 flex-wrap">
                  {asset.tags.map((tag) => (
                    <Badge key={tag} variant="outline">
                      {tag}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {asset.type === 'ip' && asset.ipInfo && (
          <Card>
            <CardHeader>
              <CardTitle>IP信息</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-sm text-muted-foreground">IP地址</p>
                  <p className="font-medium font-mono">{asset.ipInfo.ip}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">操作系统</p>
                  <p className="font-medium">{asset.ipInfo.os || '-'}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">位置</p>
                  <p className="font-medium">{asset.ipInfo.location || '-'}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">ISP</p>
                  <p className="font-medium">{asset.ipInfo.isp || '-'}</p>
                </div>
              </div>
              {asset.ipInfo.ports && asset.ipInfo.ports.length > 0 && (
                <div>
                  <p className="text-sm text-muted-foreground mb-2">开放端口</p>
                  <div className="flex gap-2 flex-wrap">
                    {asset.ipInfo.ports.map((port) => (
                      <Badge key={port} variant="secondary">
                        {port}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {asset.type === 'domain' && asset.domainInfo && (
          <Card>
            <CardHeader>
              <CardTitle>域名信息</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <p className="text-sm text-muted-foreground">域名</p>
                <p className="font-medium font-mono">{asset.domainInfo.domain}</p>
              </div>
              {asset.domainInfo.subdomains && asset.domainInfo.subdomains.length > 0 && (
                <div>
                  <p className="text-sm text-muted-foreground mb-2">子域名</p>
                  <div className="flex gap-2 flex-wrap max-h-32 overflow-auto">
                    {asset.domainInfo.subdomains.map((sub) => (
                      <Badge key={sub} variant="outline" className="font-mono text-xs">
                        {sub}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
              {asset.domainInfo.resolveIPs && asset.domainInfo.resolveIPs.length > 0 && (
                <div>
                  <p className="text-sm text-muted-foreground mb-2">解析IP</p>
                  <div className="flex gap-2 flex-wrap">
                    {asset.domainInfo.resolveIPs.map((ip) => (
                      <Badge key={ip} variant="secondary" className="font-mono">
                        {ip}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {asset.type === 'web' && asset.webInfo && (
          <Card>
            <CardHeader>
              <CardTitle>Web信息</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-sm text-muted-foreground">URL</p>
                  <p className="font-medium font-mono text-sm truncate">{asset.webInfo.url}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">标题</p>
                  <p className="font-medium truncate">{asset.webInfo.title || '-'}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">状态码</p>
                  <p className="font-medium">{asset.webInfo.statusCode || '-'}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">服务器</p>
                  <p className="font-medium">{asset.webInfo.server || '-'}</p>
                </div>
              </div>
              {asset.webInfo.technologies && asset.webInfo.technologies.length > 0 && (
                <div>
                  <p className="text-sm text-muted-foreground mb-2">技术栈</p>
                  <div className="flex gap-2 flex-wrap">
                    {asset.webInfo.technologies.map((tech) => (
                      <Badge key={tech} variant="secondary">
                        {tech}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  )
}
