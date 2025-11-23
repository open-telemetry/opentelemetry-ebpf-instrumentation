// Example NestJS controller with decorators
import { Controller, Get, Post, Put, Delete, Param, Body } from '@nestjs/common';

@Controller('users')
export class UsersController {
  @Get()
  findAll() {
    return { users: [] };
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return { userId: id };
  }

  @Post()
  create(@Body() createUserDto: any) {
    return { created: true };
  }

  @Put(':id')
  update(@Param('id') id: string, @Body() updateUserDto: any) {
    return { updated: true };
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return { deleted: true };
  }
}

@Controller('api/v1/posts')
export class PostsController {
  @Get()
  getAllPosts() {
    return { posts: [] };
  }

  @Get(':postId/comments')
  getComments(@Param('postId') postId: string) {
    return { comments: [] };
  }

  @Post(':postId/comments')
  createComment(@Param('postId') postId: string, @Body() body: any) {
    return { commentId: 456 };
  }
}

@Controller('health')
export class HealthController {
  // Empty path defaults to controller path
  @Get()
  check() {
    return { status: 'ok' };
  }
}
